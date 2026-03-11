package cryptobyte

import (
	encoding_asn1 "encoding/asn1"
	"github.com/nvx/go-cryptobyte/asn1"
	"time"
)

func AsString[T ~*[]byte](s T) *String {
	return (*String)(s)
}

func readCB[T any](fn func(out *T) bool) (T, bool) {
	var out T
	ok := fn(&out)
	return out, ok
}

func readASN1[T any](fn func(out *T, tag asn1.Tag) bool, tag asn1.Tag) (T, bool) {
	var out T
	ok := fn(&out, tag)
	return out, ok
}

func (s *String) RReadASN1Uint32() (out uint32, ok bool) {
	ok = s.ReadASN1Integer(&out)
	return
}

func (s *String) RReadOptionalASN1Uint32(tag asn1.Tag, defaultValue any) (out uint32, ok bool) {
	ok = s.ReadOptionalASN1Integer(&out, tag, defaultValue)
	return
}

func (s *String) RReadASN1Uint64() (out uint64, ok bool) {
	ok = s.ReadASN1Integer(&out)
	return
}

func (s *String) RReadOptionalASN1Uint64(tag asn1.Tag, defaultValue any) (out uint64, ok bool) {
	ok = s.ReadOptionalASN1Integer(&out, tag, defaultValue)
	return
}

func (s *String) RReadASN1Int32() (out int32, ok bool) {
	ok = s.ReadASN1Integer(&out)
	return
}

func (s *String) RReadOptionalASN1Int32(tag asn1.Tag, defaultValue any) (out int32, ok bool) {
	ok = s.ReadOptionalASN1Integer(&out, tag, defaultValue)
	return
}

func (s *String) RReadASN1Int64() (out int64, ok bool) {
	ok = s.ReadASN1Integer(&out)
	return
}

func (s *String) RReadOptionalASN1Int64(tag asn1.Tag, defaultValue any) (out int64, ok bool) {
	ok = s.ReadOptionalASN1Integer(&out, tag, defaultValue)
	return
}

func (s *String) RReadASN1Int() (out int, ok bool) {
	ok = s.ReadASN1Integer(&out)
	return
}

func (s *String) RReadOptionalASN1Int(tag asn1.Tag, defaultValue any) (out int, ok bool) {
	ok = s.ReadOptionalASN1Integer(&out, tag, defaultValue)
	return
}

func (s *String) RReadASN1(tag asn1.Tag) (String, bool) {
	return readASN1(s.ReadASN1, tag)
}

func (s *String) RReadASN1Bytes(tag asn1.Tag) ([]byte, bool) {
	return readASN1(s.ReadASN1Bytes, tag)
}

func (s *String) RReadASN1Element(tag asn1.Tag) (String, bool) {
	return readASN1(s.ReadASN1Element, tag)
}

func (s *String) RReadASN1Int64WithTag(tag asn1.Tag) (int64, bool) {
	return readASN1(s.ReadASN1Int64WithTag, tag)
}

func (s *String) RReadASN1BitString() (encoding_asn1.BitString, bool) {
	return readCB(s.ReadASN1BitString)
}

func (s *String) RReadASN1BitStringAsBytes() ([]byte, bool) {
	return readCB(s.ReadASN1BitStringAsBytes)
}

func (s *String) RReadASN1Boolean() (bool, bool) {
	return readCB(s.ReadASN1Boolean)
}

func (s *String) RReadASN1Enum() (int, bool) {
	return readCB(s.ReadASN1Enum)
}

func (s *String) RReadASN1GeneralizedTime() (time.Time, bool) {
	return readCB(s.ReadASN1GeneralizedTime)
}

func (s *String) RReadASN1ObjectIdentifier() (encoding_asn1.ObjectIdentifier, bool) {
	return readCB(s.ReadASN1ObjectIdentifier)
}

func (s *String) RReadASN1UTCTime() (time.Time, bool) {
	return readCB(s.ReadASN1UTCTime)
}

func (s *String) RReadBytes(n int) ([]byte, bool) {
	v := s.read(n)
	if v == nil {
		return nil, false
	}
	return v, true
}

func (s *String) RReadUint16() (uint16, bool) {
	return readCB(s.ReadUint16)
}

func (s *String) RReadUint16LengthPrefixed() (String, bool) {
	return readCB(s.ReadUint16LengthPrefixed)
}

func (s *String) RReadUint24() (uint32, bool) {
	return readCB(s.ReadUint24)
}

func (s *String) RReadUint24LengthPrefixed() (String, bool) {
	return readCB(s.ReadUint24LengthPrefixed)
}

func (s *String) RReadUint32() (uint32, bool) {
	return readCB(s.ReadUint32)
}

func (s *String) RReadUint48() (uint64, bool) {
	return readCB(s.ReadUint48)
}

func (s *String) RReadUint64() (uint64, bool) {
	return readCB(s.ReadUint64)
}

func (s *String) RReadUint8() (uint8, bool) {
	return readCB(s.ReadUint8)
}

func (s *String) RReadUint8LengthPrefixed() (String, bool) {
	return readCB(s.ReadUint8LengthPrefixed)
}

func (s *String) RReadOptionalASN1(tag asn1.Tag) (String, bool) {
	present := s.PeekASN1Tag(tag)
	var out String
	if present && !s.ReadASN1(&out, tag) {
		return nil, false
	}
	return out, true
}

func (s *String) RReadOptionalASN1Boolean(tag asn1.Tag, defaultValue bool) (out bool, ok bool) {
	ok = s.ReadOptionalASN1Boolean(&out, tag, defaultValue)
	return
}

func (s *String) RReadOptionalASN1OctetString(tag asn1.Tag) (out []byte, ok bool) {
	ok = s.ReadOptionalASN1OctetString(&out, nil, tag)
	return
}

func (s *String) RReadAnyASN1() (out String, outTag asn1.Tag, ok bool) {
	ok = s.ReadAnyASN1(&out, &outTag)
	return
}

func (s *String) RReadAnyASN1Element() (out String, outTag asn1.Tag, ok bool) {
	ok = s.ReadAnyASN1Element(&out, &outTag)
	return
}
