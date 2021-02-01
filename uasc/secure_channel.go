// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
)

const (
	MaxTimeout = math.MaxUint32 * time.Millisecond
)

type response struct {
	ReqID uint32
	SCID  uint32
	V     interface{}
	Err   error
}

type activeRequest struct {
	instance *channelInstance
	resp     chan *response
}

type SecureChannel struct {
	endpointURL string

	// c is the uacp connection
	c *uacp.Conn

	// cfg is the configuration for the secure channel.
	cfg *Config

	// time returns the current time. When not set it defaults to time.Now().
	time func() time.Time

	// startDispatcher ensures only one dispatcher is running
	startDispatcher sync.Once

	// requestID is a "global" counter shared between multiple channels and tokens
	requestID uint32

	// ci is the currently active channel instance
	ci  *channelInstance
	ciL sync.RWMutex

	// decryptChannel is used as a single source for decrypting incoming messages.
	// This should be possible to use as long as the security settings remain constant
	// for a single SecureChannel throughout the lifetime of the connection.
	decryptChannel *channelInstance
	dcL            sync.RWMutex

	// requests maps request IDs to an instance and response channel
	requests map[uint32]activeRequest
	reqL     sync.Mutex

	// chunks maintains a temporary list of chunks for a given request ID
	chunks   map[uint32][]*MessageChunk
	chunksMu sync.Mutex

	// errorCh receive dispatcher errors
	errCh chan<- error
	quit  chan struct{}
}

func NewSecureChannel(endpoint string, c *uacp.Conn, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	if c == nil {
		return nil, errors.Errorf("no connection")
	}

	if cfg == nil {
		return nil, errors.Errorf("no secure channel config")
	}

	if cfg.SecurityPolicyURI != ua.SecurityPolicyURINone {
		if cfg.SecurityMode == ua.MessageSecurityModeNone {
			return nil, errors.Errorf("invalid channel config: Security policy '%s' cannot be used with '%s'", cfg.SecurityPolicyURI, cfg.SecurityMode)
		}
		if cfg.LocalKey == nil {
			return nil, errors.Errorf("invalid channel config: Security policy '%s' requires a private key", cfg.SecurityPolicyURI)
		}
	}

	// Force the security mode to None if the policy is also None
	// TODO: I don't like that a SecureChannel changes the incoming config
	if cfg.SecurityPolicyURI == ua.SecurityPolicyURINone {
		cfg.SecurityMode = ua.MessageSecurityModeNone
	}

	s := &SecureChannel{
		endpointURL: endpoint,
		c:           c,
		cfg:         cfg,
		requestID:   cfg.RequestIDSeed,
		errCh:       errCh,
		quit:        make(chan struct{}),
	}
	s.reset()

	return s, nil
}

func (s *SecureChannel) reset() {
	s.startDispatcher = sync.Once{}
	s.chunks = make(map[uint32][]*MessageChunk)
	s.requests = make(map[uint32]activeRequest)
	s.quit = make(chan struct{})
}

func (s *SecureChannel) dispatcher() {
	for {
		select {
		case <-s.quit:
			return
		default:
			resp, err := s.receive()
			if err != nil {
				s.errCh <- err
				return
			}

			go s.handleResponse(resp)
		}
	}
}

func (s *SecureChannel) handleResponse(resp *response) {
	if resp.Err != nil {
		debug.Printf("uasc %d/%d: err: %v", s.c.ID(), resp.ReqID, resp.Err)
	} else {
		debug.Printf("uasc %d/%d: recv %T", s.c.ID(), resp.ReqID, resp.V)
	}

	ch, ok := s.popActiveRequest(resp.ReqID)

	if !ok {
		debug.Printf("uasc %d/%d: no handler for %T", s.c.ID(), resp.ReqID, resp.V)
		return
	}

	debug.Printf("sending %T to handler\n", resp.V)

	ch <- resp
}

// receive receives message chunks from the secure channel, decodes and forwards
// them to the registered callback channel, if there is one. Otherwise,
// the message is dropped. The returned error here indicates a transport level error,
// some issue with the network that cannot be resolved. It is explicitly NOT an OPC
// UA protocol level error!
func (s *SecureChannel) receive() (*response, error) {
	for {
		select {
		case <-s.quit:
			return nil, io.EOF
		default:
			chunk, err := s.readChunk()
			if err == io.EOF {
				debug.Printf("uasc readChunk EOF")
				return nil, err
			} else if _, ok := err.(net.Error); ok {
				return nil, err
			} else if err != nil {
				return &response{Err: err}, nil
			}

			hdr := chunk.Header
			reqID := chunk.SequenceHeader.RequestID

			resp := &response{
				ReqID: reqID,
				SCID:  chunk.MessageHeader.Header.SecureChannelID,
			}

			debug.Printf("uasc %d/%d: recv %s%c with %d bytes", s.c.ID(), reqID, hdr.MessageType, hdr.ChunkType, hdr.MessageSize)

			s.chunksMu.Lock()

			switch hdr.ChunkType {
			case 'A':
				delete(s.chunks, reqID)
				s.chunksMu.Unlock()

				msga := new(MessageAbort)
				if _, err := msga.Decode(chunk.Data); err != nil {
					debug.Printf("conn %d/%d: invalid MSGA chunk. %s", s.c.ID(), reqID, err)
					resp.Err = ua.StatusBadDecodingError
					return resp, nil
				}

				return &response{ReqID: reqID, Err: ua.StatusCode(msga.ErrorCode)}, nil

			case 'C':
				s.chunks[reqID] = append(s.chunks[reqID], chunk)
				if n := len(s.chunks[reqID]); uint32(n) > s.c.MaxChunkCount() {
					delete(s.chunks, reqID)
					s.chunksMu.Unlock()
					resp.Err = errors.Errorf("too many chunks: %d > %d", n, s.c.MaxChunkCount())
					return resp, nil
				}
				s.chunksMu.Unlock()
				continue
			}

			// merge chunks
			all := append(s.chunks[reqID], chunk)
			delete(s.chunks, reqID)

			s.chunksMu.Unlock()

			b, err := mergeChunks(all)
			if err != nil {
				resp.Err = err
				return resp, nil
			}

			if uint32(len(b)) > s.c.MaxMessageSize() {
				resp.Err = errors.Errorf("message too large: %d > %d", uint32(len(b)), s.c.MaxMessageSize())
				return resp, nil
			}

			// since we are not decoding the ResponseHeader separately
			// we need to drop every message that has an error since we
			// cannot get to the RequestHandle in the ResponseHeader.
			// To fix this we must a) decode the ResponseHeader separately
			// and subsequently remove it and the TypeID from all service
			// structs and tests. We also need to add a deadline to all
			// handlers and check them periodically to time them out.
			_, svc, err := ua.DecodeService(b)
			if err != nil {
				resp.Err = err
				return resp, nil
			}

			resp.V = svc

			// If the service status is not OK then bubble
			// that error up to the caller.
			if r, ok := svc.(ua.Response); ok {
				if status := r.Header().ServiceResult; status != ua.StatusOK {
					resp.Err = status
					return resp, nil
				}
			}

			return resp, nil
		}
	}
}

func (s *SecureChannel) readChunk() (*MessageChunk, error) {
	// read a full message from the underlying conn.
	b, err := s.c.Receive()
	if err == io.EOF || len(b) == 0 {
		return nil, io.EOF
	}
	// do not wrap this error since it hides conn error
	if _, ok := err.(*uacp.Error); ok {
		return nil, err
	}
	if err != nil {
		return nil, errors.Errorf("sechan: read header failed: %s %#v", err, err)
	}

	const hdrlen = 12 // TODO: move to pkg level const
	h := new(Header)
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, errors.Errorf("sechan: decode header failed: %s", err)
	}

	// decode the other headers
	m := new(MessageChunk)
	if _, err := m.Decode(b); err != nil {
		return nil, errors.Errorf("sechan: decode chunk failed: %s", err)
	}

	switch m.MessageType {
	case "OPN":
		debug.Printf("uasc OPN Request")

		// Make sure we have a valid security header
		if m.AsymmetricSecurityHeader == nil {
			return nil, ua.StatusBadDecodingError // todo(dh): check if this is the correct error
		}

		if m.SecurityPolicyURI != ua.SecurityPolicyURINone {
			s.cfg.RemoteCertificate = m.AsymmetricSecurityHeader.SenderCertificate
			debug.Printf("Setting securityPolicy to %s", m.SecurityPolicyURI)
		}

		s.cfg.SecurityPolicyURI = m.SecurityPolicyURI
	case "CLO":
		return nil, io.EOF
	case "MSG":
		// nop
	default:
		return nil, errors.Errorf("sechan: unknown message type: %s", m.MessageType)
	}

	s.dcL.RLock()

	if s.decryptChannel == nil {
		return nil, errors.New("receiving data with no decrypt channel, how?")
	}

	m.Data, err = s.decryptChannel.verifyAndDecrypt(m, b)
	if err != nil {
		return nil, err
	}

	s.dcL.RUnlock()

	n, err := m.SequenceHeader.Decode(m.Data)
	if err != nil {
		return nil, errors.Errorf("sechan: decode sequence header failed: %s", err)
	}
	m.Data = m.Data[n:]

	return m, nil
}

func (s *SecureChannel) LocalEndpoint() string {
	return s.endpointURL
}

func (s *SecureChannel) Open(ctx context.Context) error {
	return s.open(ctx, nil, ua.SecurityTokenRequestTypeIssue)
}

func (s *SecureChannel) open(ctx context.Context, prev *channelInstance, requestType ua.SecurityTokenRequestType) error {
	var (
		err       error
		localKey  *rsa.PrivateKey
		remoteKey *rsa.PublicKey
		instance  *channelInstance
	)

	s.startDispatcher.Do(func() {
		go s.dispatcher()
	})

	// Set the encryption methods to Asymmetric with the appropriate
	// public keys.  OpenSecureChannel is always encrypted with the
	// asymmetric algorithms.
	// The default value of the encryption algorithm method is the
	// SecurityModeNone so no additional work is required for that case
	if s.cfg.SecurityMode != ua.MessageSecurityModeNone {
		localKey = s.cfg.LocalKey
		// todo(dh): move this into the uapolicy package proper or
		// adjust the Asymmetric method to receive a certificate instead
		remoteCert, err := x509.ParseCertificate(s.cfg.RemoteCertificate)
		if err != nil {
			return err
		}
		var ok bool
		if remoteKey, ok = remoteCert.PublicKey.(*rsa.PublicKey); !ok {
			return ua.StatusBadCertificateInvalid
		}
	}

	algo, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	s.dcL.Lock()

	// this is possible only as long as the assumption that security settings will not change
	// for a single session holds. Please keep it, it massively simplifies instance management
	if s.decryptChannel == nil {
		s.decryptChannel = &channelInstance{
			sc:   s,
			algo: algo,
		}
	}

	s.dcL.Unlock()

	instance = newChannelInstance(s)

	if requestType == ua.SecurityTokenRequestTypeRenew {
		if prev == nil {
			return errors.New("attempted to renew a non-existent channel")
		}

		// TODO: lock? sequenceNumber++?
		// this seems racy. if another request goes out while the other open request is in flight then won't an error
		// be raised on the server? can the sequenceNumber be as "global" as the request ID?
		instance.sequenceNumber = prev.sequenceNumber
		instance.secureChannelID = prev.secureChannelID
	}

	reqID := s.nextRequestID()

	s.dcL.RLock()

	instance.algo = s.decryptChannel.algo

	s.dcL.RUnlock()

	localNonce, err := instance.algo.MakeNonce()
	if err != nil {
		return err
	}

	req := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: 0,
		RequestType:           requestType,
		SecurityMode:          s.cfg.SecurityMode,
		ClientNonce:           localNonce,
		RequestedLifetime:     s.cfg.Lifetime,
	}

	resp, err := s.sendRequestWithTimeout(ctx, req, reqID, instance, nil)
	if err != nil {
		return err
	}

	if resp.Err != nil {
		return resp.Err
	}

	openResp, ok := resp.V.(*ua.OpenSecureChannelResponse)
	if !ok {
		return errors.Errorf("got %T, want OpenSecureChannelResponse", resp.V)
	}

	return s.handleOpenSecureChannelResponse(openResp, localNonce, instance)
}

func (s *SecureChannel) handleOpenSecureChannelResponse(resp *ua.OpenSecureChannelResponse, localNonce []byte, instance *channelInstance) (err error) {
	instance.secureChannelID = resp.SecurityToken.ChannelID
	instance.securityTokenID = resp.SecurityToken.TokenID
	instance.createdAt = resp.SecurityToken.CreatedAt
	instance.revisedLifetime = time.Millisecond * time.Duration(resp.SecurityToken.RevisedLifetime)

	// allow the client to specify a lifetime that is smaller
	if int64(s.cfg.Lifetime) < int64(instance.revisedLifetime/time.Millisecond) {
		instance.revisedLifetime = time.Millisecond * time.Duration(s.cfg.Lifetime)
	}

	if instance.algo, err = uapolicy.Symmetric(s.cfg.SecurityPolicyURI, localNonce, resp.ServerNonce); err != nil {
		return err
	}

	s.ciL.Lock()
	defer s.ciL.Unlock()

	s.ci = instance

	debug.Printf("received security token: channelID=%d tokenID=%d createdAt=%s lifetime=%s", instance.secureChannelID, instance.securityTokenID, instance.createdAt.Format(time.RFC3339), instance.revisedLifetime)

	go s.scheduleRenewal(instance)

	return
}

func (s *SecureChannel) scheduleRenewal(instance *channelInstance) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should request a new SecurityToken after 75 % of its lifetime has elapsed. This should ensure that
	// clients will receive the new SecurityToken before the old one actually expire
	const renewAfter = 0.75
	when := instance.createdAt.Add(time.Second * time.Duration(instance.revisedLifetime.Seconds()*renewAfter))

	debug.Printf("channelID %d will be refreshed in %ds (%s)", instance.secureChannelID, when.Second(), when.Format(time.RFC3339))

	select {
	case <-s.quit:
		return
	case <-time.After(time.Until(when)):
	}

	fmt.Println("RENEWING")

	// TODO: where should this error go?
	if err := s.renew(instance); err != nil {
		s.errCh <- err
	}

	go s.scheduleRemoval(instance)
}

func (s *SecureChannel) scheduleRemoval(inst *channelInstance) {
	<-time.After(10 * time.Second)

	s.reqL.Lock()
	defer s.reqL.Unlock()

	oldReqs := s.requests
	removed := 0

	for reqId, req := range oldReqs {
		if req.instance == inst {
			close(req.resp)
			delete(s.requests, reqId)

			removed++
		}
	}

	fmt.Printf("REQUEST CLEANUP removed=%d\n", removed)
}

func (s *SecureChannel) renew(instance *channelInstance) error {
	return s.open(context.Background(), instance, ua.SecurityTokenRequestTypeRenew)
}

func (s *SecureChannel) sendRequestWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstance,
	authToken *ua.NodeID) (*response, error) {

	ch, err := s.sendAsyncWithTimeout(ctx, req, reqID, instance, authToken)
	if err != nil {
		return nil, err
	}

	select {
	case <-s.quit:
		s.popActiveRequest(reqID)
		return nil, io.EOF
	case resp, ok := <-ch:
		if !ok {
			// this signifies an interrupted response, quite likely due to a close request
			return nil, io.EOF
		}

		return resp, nil
	case <-ctx.Done():
		s.popActiveRequest(reqID)
		return nil, ua.StatusBadTimeout
	}
}

func (s *SecureChannel) popActiveRequest(tokenID uint32) (chan *response, bool) {
	s.reqL.Lock()
	defer s.reqL.Unlock()

	req, ok := s.requests[tokenID]
	if ok {
		delete(s.requests, tokenID)
	}

	return req.resp, ok
}

func (s *SecureChannel) Renew(ctx context.Context) error {
	s.ciL.RLock()

	if s.ci != nil {
		return errors.New("cannot renew non-existent secure channel")
	}

	instance := s.ci

	s.ciL.RUnlock()

	return s.renew(instance)
}

// SendRequest sends the service request and calls h with the response.
func (s *SecureChannel) SendRequest(req ua.Request, authToken *ua.NodeID, h func(interface{}) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
	defer cancel()

	return s.SendRequestWithTimeout(ctx, req, authToken, h)
}

func (s *SecureChannel) SendRequestWithTimeout(ctx context.Context, req ua.Request, authToken *ua.NodeID, h func(interface{}) error) error {
	s.ciL.RLock()

	if s.ci == nil {
		return errors.New("no active secure channel instance")
	}

	instance := s.ci

	s.ciL.RUnlock()

	respRequired := h != nil

	resp, err := s.sendRequestWithTimeout(ctx, req, s.nextRequestID(), instance, authToken)
	if err != nil {
		return err
	}

	if resp.Err != nil {
		return resp.Err
	}

	if respRequired {
		return h(resp.V)
	}

	return nil
}

func (s *SecureChannel) sendAsyncWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstance,
	authToken *ua.NodeID,
) (<-chan *response, error) {

	m, err := instance.newRequestMessage(ctx, req, reqID, authToken)
	if err != nil {
		return nil, err
	}

	b, err := m.Encode()
	if err != nil {
		return nil, err
	}

	b, err = instance.signAndEncrypt(m, b)
	if err != nil {
		return nil, err
	}

	ar := activeRequest{
		instance: instance,
		resp:     make(chan *response, 1),
	}

	s.reqL.Lock()
	s.requests[reqID] = ar
	s.reqL.Unlock()

	// send the message
	var n int
	if n, err = s.c.Write(b); err != nil {
		if _, ok := err.(net.Error); ok {
			s.errCh <- err
		}

		return nil, err
	}

	atomic.AddUint64(&instance.bytesSent, uint64(n))
	atomic.AddUint32(&instance.messagesSent, 1)

	debug.Printf("uasc %d/%d: send %T with %d bytes", s.c.ID(), reqID, req, len(b))

	return ar.resp, nil
}

func (s *SecureChannel) nextRequestID() uint32 {
	ret := atomic.AddUint32(&s.requestID, 1)
	if ret == 0 {
		return atomic.AddUint32(&s.requestID, 1)
	}

	return ret
}

// Close closes an existing secure channel
func (s *SecureChannel) Close() error {
	debug.Printf("uasc Close()")

	err := s.SendRequest(&ua.CloseSecureChannelRequest{}, nil, nil)
	if err != nil {
		return err
	}

	close(s.quit)
	close(s.errCh)

	s.ciL.Lock()
	defer s.ciL.Unlock()

	s.ci = nil

	s.reqL.Lock()
	defer s.reqL.Unlock()

	for _, req := range s.requests {
		close(req.resp)
	}

	s.requests = make(map[uint32]activeRequest)

	return io.EOF
}

func (s *SecureChannel) timeNow() time.Time {
	if s.time != nil {
		return s.time()
	}
	return time.Now()
}

func mergeChunks(chunks []*MessageChunk) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, nil
	}
	if len(chunks) == 1 {
		return chunks[0].Data, nil
	}

	// todo(fs): check if this is correct and necessary
	// sort.Sort(bySequence(chunks))

	var (
		b     []byte
		seqnr uint32
	)

	for _, c := range chunks {
		if c.SequenceHeader.SequenceNumber == seqnr {
			continue // duplicate chunk
		}
		seqnr = c.SequenceHeader.SequenceNumber
		b = append(b, c.Data...)
	}
	return b, nil
}

// todo(fs): we only need this if we need to sort chunks. Need to check the spec
// type bySequence []*MessageChunk

// func (a bySequence) Len() int      { return len(a) }
// func (a bySequence) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
// func (a bySequence) Less(i, j int) bool {
// 	return a[i].SequenceHeader.SequenceNumber < a[j].SequenceHeader.SequenceNumber
// }
