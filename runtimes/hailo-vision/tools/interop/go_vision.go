// Build in an isolated module with a pinned copy of LiNeP-Ollama/pkg/linep/v02
// in ./codec (standard library only). No production codec is reimplemented here.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	v02 "visioninterop/codec"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, reason string) {
	if !ok {
		panic(reason)
	}
}
func mustBytes(b []byte, e error) []byte { check(e); return b }

func verifyDirectory(dir string) {
	for _, name := range []string{"capabilities.bin", "request.bin", "vision_result.bin", "terminal.bin"} {
		raw, e := os.ReadFile(filepath.Join(dir, name))
		check(e)
		var out []byte
		switch name {
		case "capabilities.bin":
			v, e := v02.DecodeCapabilities(raw)
			check(e)
			out = mustBytes(v02.EncodeCapabilities(v))
		case "request.bin":
			v, e := v02.DecodeRequest(raw)
			check(e)
			out = mustBytes(v02.EncodeRequest(v))
		default:
			v, e := v02.DecodeEvent(raw)
			check(e)
			out = mustBytes(v02.EncodeEvent(v))
		}
		require(bytes.Equal(raw, out), "Go byte drift")
	}
	invalid, e := filepath.Glob(filepath.Join(dir, "invalid_*.bin"))
	check(e)
	for _, path := range invalid {
		raw, e := os.ReadFile(path)
		check(e)
		_, e = v02.DecodeEvent(raw)
		require(e != nil, "Go accepted invalid vision event")
	}
	report, _ := json.Marshal(map[string]any{"language": "go", "passed": true, "roundtrip_frames": 4, "invalid_rejected": len(invalid)})
	fmt.Println(string(report))
}

func main() {
	host := flag.String("host", "127.0.0.1", "")
	port := flag.Int("port", 11436, "")
	control := flag.Int("control-port", 9001, "")
	keyFile := flag.String("key-file", "", "")
	imageFile := flag.String("image", "", "bus.jpg fixture")
	out := flag.String("out-dir", "", "capture directory")
	model := flag.String("model", "yolov8s-detect", "")
	verify := flag.String("verify-dir", "", "verify captures instead of connecting")
	flag.Parse()
	if *verify != "" {
		verifyDirectory(*verify)
		return
	}
	require(*imageFile != "" && *out != "", "image and out-dir required")
	image, err := os.ReadFile(*imageFile)
	check(err)
	require(len(image) > 0, "empty image")
	check(os.MkdirAll(*out, 0700))
	save := func(name string, b []byte) { check(os.WriteFile(filepath.Join(*out, name), b, 0600)) }
	var key []byte
	var keyID uint16
	var bind v02.SessionBindEnvelope
	if *keyFile != "" {
		text, e := os.ReadFile(*keyFile)
		check(e)
		for _, line := range strings.Split(string(text), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch strings.TrimSpace(parts[0]) {
			case "key_id":
				n, e := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
				check(e)
				keyID = uint16(n)
			case "key":
				key, e = hex.DecodeString(strings.TrimSpace(parts[1]))
				check(e)
			}
		}
		require(keyID > 0 && len(key) >= 32, "invalid credentials")
		var random [16]byte
		_, e = rand.Read(random[:])
		check(e)
		bind.Identity = v02.NodeEndpointIdentity{NodeID: binary.LittleEndian.Uint64(random[:8]) | 1, RuntimeID: 3, EndpointID: 1}
		bind.ControlEpoch = binary.LittleEndian.Uint64(random[8:]) | 1
		addr, e := net.ResolveUDPAddr("udp4", net.JoinHostPort(*host, strconv.Itoa(*control)))
		check(e)
		udp, e := net.DialUDP("udp4", nil, addr)
		check(e)
		defer udp.Close()
		check(udp.SetDeadline(time.Now().Add(5 * time.Second)))
		hello := v02.UDPControlDatagram{Magic: 0x504e4c55, VersionMinor: 2, MessageType: 1, Flags: 1, NodeID: bind.Identity.NodeID, RuntimeID: 3, EndpointID: 1, ControlEpoch: bind.ControlEpoch, ControlSeq: 1, Availability: 2, Health: 1, TCPPort: 40000}
		_, e = udp.Write(v02.EncodeControlDatagram(hello))
		check(e)
		b := make([]byte, 256)
		n, e := udp.Read(b)
		check(e)
		invite, e := v02.DecodeControlDatagram(b[:n])
		check(e)
		require(invite.MessageType == 4 && invite.NodeID == hello.NodeID && invite.RuntimeID == 3 && invite.EndpointID == 1 && invite.ControlEpoch == hello.ControlEpoch && invite.LeaseToken > 0, "invalid INVITE")
		bind.LeaseToken = invite.LeaseToken
		hello.MessageType = 5
		hello.ControlSeq = 2
		hello.LeaseToken = invite.LeaseToken
		_, e = udp.Write(v02.EncodeControlDatagram(hello))
		check(e)
		time.Sleep(200 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(*host, strconv.Itoa(*port)), 5*time.Second)
	check(err)
	defer conn.Close()
	var outSeq, inSeq uint32
	send := func(raw []byte) {
		if len(key) > 0 {
			outSeq++
			raw = mustBytes(v02.SignEnvelopeBuffer(raw, bind, v02.DirectionInitiatorToResponder, outSeq, keyID, key))
		}
		check(conn.SetWriteDeadline(time.Now().Add(15 * time.Second)))
		_, e := io.Copy(conn, bytes.NewReader(raw))
		check(e)
	}
	receive := func() []byte {
		check(conn.SetReadDeadline(time.Now().Add(15 * time.Second)))
		header := make([]byte, 32)
		_, e := io.ReadFull(conn, header)
		check(e)
		h, e := v02.DecodeHeader(header)
		check(e)
		require(h.Magic == v02.Magic && h.VersionMajor == 0 && h.VersionMinor == 2 && h.PayloadLen <= v02.MaxPayloadBytes, "invalid frame header")
		ext := 0
		if h.Flags&v02.FlagAuthenticated != 0 {
			ext = 24
		}
		rest := make([]byte, int(h.PayloadLen)+ext)
		_, e = io.ReadFull(conn, rest)
		check(e)
		raw := append(header, rest...)
		if len(key) > 0 {
			a, e := v02.VerifyEnvelopeBuffer(raw, bind, v02.DirectionResponderToInitiator, key)
			check(e)
			require(a.AuthSeq > inSeq && a.KeyID == keyID, "wrong key or replay")
			inSeq = a.AuthSeq
		}
		return raw
	}
	if len(key) > 0 {
		send(mustBytes(v02.EncodeSessionBind(bind)))
		confirmed, e := v02.DecodeSessionBind(receive())
		check(e)
		require(confirmed.Identity == bind.Identity && confirmed.ControlEpoch == bind.ControlEpoch && confirmed.LeaseToken == bind.LeaseToken, "bind not confirmed")
	}
	send(mustBytes(v02.EncodeCapabilities(v02.CapabilitiesEnvelope{})))
	caps, err := v02.DecodeCapabilities(receive())
	check(err)
	require(caps.Descriptor.SupportsVisionModel("yolov8s-detect", v02.VisionTaskDetect), "VISION discovery failed")
	revision := ""
	for _, m := range caps.Descriptor.SupportedVisionModels {
		if m.ModelID == "yolov8s-detect" {
			revision = m.ModelRevision
		}
	}
	save("capabilities.bin", mustBytes(v02.EncodeCapabilities(caps)))
	options := v02.DefaultGenerationOptions()
	options.ExtraOptions = [][2]string{{"vision.task", "detect"}}
	req := v02.RequestEnvelope{Stream: v02.StreamIdentity{RequestID: 89001, ExecutionID: 890010}, Profile: v02.ProfileVision, ModelID: *model, Payload: string(image), HasOptions: true, Options: options}
	raw := mustBytes(v02.EncodeRequest(req))
	save("request.bin", raw)
	send(raw)
	labels := map[string]bool{}
	results := 0
	for seq := uint64(1); seq <= 4; seq++ {
		evt, e := v02.DecodeEvent(receive())
		check(e)
		require(evt.Stream == req.Stream && evt.EventSeq == seq, "stream/sequence mismatch")
		if seq == 1 {
			require(evt.EventType == v02.EventTypeAccepted, "missing ACCEPTED")
		}
		if evt.EventType == v02.EventTypeVisionResult {
			results++
			v := evt.Vision
			require(seq == 2 && v.IsValid() && v.ModelID == "yolov8s-detect" && v.ModelRevision == revision && v.Detect.LabelSetID == "coco80:v1" && v.Detect.OriginalWidth == 810 && v.Detect.OriginalHeight == 1080, "invalid result attribution/geometry")
			for _, d := range v.Detect.Detections {
				require(v02.IsValidVisionLabel("coco80:v1", d.ClassID, d.Label), "invalid label")
				labels[d.Label] = true
			}
			save("vision_result.bin", mustBytes(v02.EncodeEvent(evt)))
		}
		if evt.IsTerminal() {
			require(evt.EventType == v02.EventTypeCompleted && evt.Outcome == v02.OutcomeCompleted && seq == 3 && results == 1 && labels["bus"] && labels["person"], "unexpected terminal or missing objects")
			save("terminal.bin", mustBytes(v02.EncodeEvent(evt)))
			send(mustBytes(v02.EncodeCapabilities(v02.CapabilitiesEnvelope{})))
			_, e = v02.DecodeCapabilities(receive())
			check(e)
			report, _ := json.Marshal(map[string]any{"language": "go", "passed": true, "sl1": len(key) > 0, "vision_results": results, "labels": []string{"bus", "person"}})
			fmt.Println(string(report))
			return
		}
	}
	panic("missing terminal")
}
