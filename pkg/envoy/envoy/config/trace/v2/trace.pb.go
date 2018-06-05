// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/trace/v2/trace.proto

package v2

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
import _struct "github.com/golang/protobuf/ptypes/struct"
import _ "github.com/lyft/protoc-gen-validate/validate"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// The tracing configuration specifies global
// settings for the HTTP tracer used by Envoy. The configuration is defined by
// the :ref:`Bootstrap <envoy_api_msg_config.bootstrap.v2.Bootstrap>` :ref:`tracing
// <envoy_api_field_config.bootstrap.v2.Bootstrap.tracing>` field. Envoy may support other tracers
// in the future, but right now the HTTP tracer is the only one supported.
type Tracing struct {
	// Provides configuration for the HTTP tracer.
	Http                 *Tracing_Http `protobuf:"bytes,1,opt,name=http" json:"http,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Tracing) Reset()         { *m = Tracing{} }
func (m *Tracing) String() string { return proto.CompactTextString(m) }
func (*Tracing) ProtoMessage()    {}
func (*Tracing) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{0}
}
func (m *Tracing) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tracing.Unmarshal(m, b)
}
func (m *Tracing) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tracing.Marshal(b, m, deterministic)
}
func (dst *Tracing) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tracing.Merge(dst, src)
}
func (m *Tracing) XXX_Size() int {
	return xxx_messageInfo_Tracing.Size(m)
}
func (m *Tracing) XXX_DiscardUnknown() {
	xxx_messageInfo_Tracing.DiscardUnknown(m)
}

var xxx_messageInfo_Tracing proto.InternalMessageInfo

func (m *Tracing) GetHttp() *Tracing_Http {
	if m != nil {
		return m.Http
	}
	return nil
}

type Tracing_Http struct {
	// The name of the HTTP trace driver to instantiate. The name must match a
	// supported HTTP trace driver. *envoy.lightstep*, *envoy.zipkin*, and
	// *envoy.dynamic.ot* are built-in trace drivers.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// Trace driver specific configuration which depends on the driver being
	// instantiated. See the :ref:`LightstepConfig
	// <envoy_api_msg_config.trace.v2.LightstepConfig>`, :ref:`ZipkinConfig
	// <envoy_api_msg_config.trace.v2.ZipkinConfig>`, and :ref:`DynamicOtConfig
	// <envoy_api_msg_config.trace.v2.DynamicOtConfig>` trace drivers for examples.
	Config               *_struct.Struct `protobuf:"bytes,2,opt,name=config" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Tracing_Http) Reset()         { *m = Tracing_Http{} }
func (m *Tracing_Http) String() string { return proto.CompactTextString(m) }
func (*Tracing_Http) ProtoMessage()    {}
func (*Tracing_Http) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{0, 0}
}
func (m *Tracing_Http) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tracing_Http.Unmarshal(m, b)
}
func (m *Tracing_Http) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tracing_Http.Marshal(b, m, deterministic)
}
func (dst *Tracing_Http) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tracing_Http.Merge(dst, src)
}
func (m *Tracing_Http) XXX_Size() int {
	return xxx_messageInfo_Tracing_Http.Size(m)
}
func (m *Tracing_Http) XXX_DiscardUnknown() {
	xxx_messageInfo_Tracing_Http.DiscardUnknown(m)
}

var xxx_messageInfo_Tracing_Http proto.InternalMessageInfo

func (m *Tracing_Http) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Tracing_Http) GetConfig() *_struct.Struct {
	if m != nil {
		return m.Config
	}
	return nil
}

// Configuration for the LightStep tracer.
type LightstepConfig struct {
	// The cluster manager cluster that hosts the LightStep collectors.
	CollectorCluster string `protobuf:"bytes,1,opt,name=collector_cluster,json=collectorCluster" json:"collector_cluster,omitempty"`
	// File containing the access token to the `LightStep
	// <http://lightstep.com/>`_ API.
	AccessTokenFile      string   `protobuf:"bytes,2,opt,name=access_token_file,json=accessTokenFile" json:"access_token_file,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LightstepConfig) Reset()         { *m = LightstepConfig{} }
func (m *LightstepConfig) String() string { return proto.CompactTextString(m) }
func (*LightstepConfig) ProtoMessage()    {}
func (*LightstepConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{1}
}
func (m *LightstepConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LightstepConfig.Unmarshal(m, b)
}
func (m *LightstepConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LightstepConfig.Marshal(b, m, deterministic)
}
func (dst *LightstepConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LightstepConfig.Merge(dst, src)
}
func (m *LightstepConfig) XXX_Size() int {
	return xxx_messageInfo_LightstepConfig.Size(m)
}
func (m *LightstepConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LightstepConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LightstepConfig proto.InternalMessageInfo

func (m *LightstepConfig) GetCollectorCluster() string {
	if m != nil {
		return m.CollectorCluster
	}
	return ""
}

func (m *LightstepConfig) GetAccessTokenFile() string {
	if m != nil {
		return m.AccessTokenFile
	}
	return ""
}

type ZipkinConfig struct {
	// The cluster manager cluster that hosts the Zipkin collectors. Note that the
	// Zipkin cluster must be defined in the :ref:`Bootstrap static cluster
	// resources <envoy_api_field_config.bootstrap.v2.Bootstrap.StaticResources.clusters>`.
	CollectorCluster string `protobuf:"bytes,1,opt,name=collector_cluster,json=collectorCluster" json:"collector_cluster,omitempty"`
	// The API endpoint of the Zipkin service where the spans will be sent. When
	// using a standard Zipkin installation, the API endpoint is typically
	// /api/v1/spans, which is the default value.
	CollectorEndpoint string `protobuf:"bytes,2,opt,name=collector_endpoint,json=collectorEndpoint" json:"collector_endpoint,omitempty"`
	// Determines whether a 128bit trace id will be used when creating a new
	// trace instance. The default value is false, which will result in a 64 bit trace id being used.
	TraceId_128Bit       bool     `protobuf:"varint,3,opt,name=trace_id_128bit,json=traceId128bit" json:"trace_id_128bit,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ZipkinConfig) Reset()         { *m = ZipkinConfig{} }
func (m *ZipkinConfig) String() string { return proto.CompactTextString(m) }
func (*ZipkinConfig) ProtoMessage()    {}
func (*ZipkinConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{2}
}
func (m *ZipkinConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ZipkinConfig.Unmarshal(m, b)
}
func (m *ZipkinConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ZipkinConfig.Marshal(b, m, deterministic)
}
func (dst *ZipkinConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ZipkinConfig.Merge(dst, src)
}
func (m *ZipkinConfig) XXX_Size() int {
	return xxx_messageInfo_ZipkinConfig.Size(m)
}
func (m *ZipkinConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_ZipkinConfig.DiscardUnknown(m)
}

var xxx_messageInfo_ZipkinConfig proto.InternalMessageInfo

func (m *ZipkinConfig) GetCollectorCluster() string {
	if m != nil {
		return m.CollectorCluster
	}
	return ""
}

func (m *ZipkinConfig) GetCollectorEndpoint() string {
	if m != nil {
		return m.CollectorEndpoint
	}
	return ""
}

func (m *ZipkinConfig) GetTraceId_128Bit() bool {
	if m != nil {
		return m.TraceId_128Bit
	}
	return false
}

// DynamicOtConfig is used to dynamically load a tracer from a shared library
// that implements the `OpenTracing dynamic loading API
// <https://github.com/opentracing/opentracing-cpp>`_.
type DynamicOtConfig struct {
	// Dynamic library implementing the `OpenTracing API
	// <https://github.com/opentracing/opentracing-cpp>`_.
	Library string `protobuf:"bytes,1,opt,name=library" json:"library,omitempty"`
	// The configuration to use when creating a tracer from the given dynamic
	// library.
	Config               *_struct.Struct `protobuf:"bytes,2,opt,name=config" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *DynamicOtConfig) Reset()         { *m = DynamicOtConfig{} }
func (m *DynamicOtConfig) String() string { return proto.CompactTextString(m) }
func (*DynamicOtConfig) ProtoMessage()    {}
func (*DynamicOtConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{3}
}
func (m *DynamicOtConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DynamicOtConfig.Unmarshal(m, b)
}
func (m *DynamicOtConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DynamicOtConfig.Marshal(b, m, deterministic)
}
func (dst *DynamicOtConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DynamicOtConfig.Merge(dst, src)
}
func (m *DynamicOtConfig) XXX_Size() int {
	return xxx_messageInfo_DynamicOtConfig.Size(m)
}
func (m *DynamicOtConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_DynamicOtConfig.DiscardUnknown(m)
}

var xxx_messageInfo_DynamicOtConfig proto.InternalMessageInfo

func (m *DynamicOtConfig) GetLibrary() string {
	if m != nil {
		return m.Library
	}
	return ""
}

func (m *DynamicOtConfig) GetConfig() *_struct.Struct {
	if m != nil {
		return m.Config
	}
	return nil
}

// Configuration structure.
type TraceServiceConfig struct {
	// The upstream gRPC cluster that hosts the metrics service.
	GrpcService          *core.GrpcService `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService" json:"grpc_service,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *TraceServiceConfig) Reset()         { *m = TraceServiceConfig{} }
func (m *TraceServiceConfig) String() string { return proto.CompactTextString(m) }
func (*TraceServiceConfig) ProtoMessage()    {}
func (*TraceServiceConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_trace_a81ab72327afe3d6, []int{4}
}
func (m *TraceServiceConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TraceServiceConfig.Unmarshal(m, b)
}
func (m *TraceServiceConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TraceServiceConfig.Marshal(b, m, deterministic)
}
func (dst *TraceServiceConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TraceServiceConfig.Merge(dst, src)
}
func (m *TraceServiceConfig) XXX_Size() int {
	return xxx_messageInfo_TraceServiceConfig.Size(m)
}
func (m *TraceServiceConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_TraceServiceConfig.DiscardUnknown(m)
}

var xxx_messageInfo_TraceServiceConfig proto.InternalMessageInfo

func (m *TraceServiceConfig) GetGrpcService() *core.GrpcService {
	if m != nil {
		return m.GrpcService
	}
	return nil
}

func init() {
	proto.RegisterType((*Tracing)(nil), "envoy.config.trace.v2.Tracing")
	proto.RegisterType((*Tracing_Http)(nil), "envoy.config.trace.v2.Tracing.Http")
	proto.RegisterType((*LightstepConfig)(nil), "envoy.config.trace.v2.LightstepConfig")
	proto.RegisterType((*ZipkinConfig)(nil), "envoy.config.trace.v2.ZipkinConfig")
	proto.RegisterType((*DynamicOtConfig)(nil), "envoy.config.trace.v2.DynamicOtConfig")
	proto.RegisterType((*TraceServiceConfig)(nil), "envoy.config.trace.v2.TraceServiceConfig")
}

func init() {
	proto.RegisterFile("envoy/config/trace/v2/trace.proto", fileDescriptor_trace_a81ab72327afe3d6)
}

var fileDescriptor_trace_a81ab72327afe3d6 = []byte{
	// 444 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x92, 0xcd, 0x6e, 0x13, 0x31,
	0x14, 0x85, 0xe5, 0x74, 0x68, 0xe9, 0x6d, 0x51, 0x5a, 0x4b, 0xa8, 0x51, 0x04, 0x28, 0xa4, 0x08,
	0x75, 0xe5, 0x11, 0x83, 0x80, 0xae, 0x5b, 0x7e, 0x25, 0x10, 0xd2, 0xb4, 0x62, 0xd1, 0xcd, 0xc8,
	0x71, 0x9c, 0xa9, 0x55, 0xd7, 0xb6, 0x3c, 0x37, 0x23, 0x65, 0xc7, 0x9a, 0x47, 0xe0, 0x09, 0x78,
	0x06, 0x56, 0xbc, 0x0e, 0x6f, 0x81, 0xc6, 0x76, 0x68, 0x50, 0xd8, 0x20, 0x76, 0xf6, 0x3d, 0xe7,
	0xf8, 0x7e, 0x9a, 0x39, 0xf0, 0x50, 0x9a, 0xd6, 0x2e, 0x72, 0x61, 0xcd, 0x4c, 0xd5, 0x39, 0x7a,
	0x2e, 0x64, 0xde, 0x16, 0xf1, 0xc0, 0x9c, 0xb7, 0x68, 0xe9, 0xdd, 0x60, 0x61, 0xd1, 0xc2, 0xa2,
	0xd2, 0x16, 0xc3, 0x47, 0x31, 0xc9, 0x9d, 0xea, 0x02, 0xc2, 0x7a, 0x99, 0xd7, 0xde, 0x89, 0xaa,
	0x91, 0xbe, 0x55, 0xcb, 0xf0, 0xf0, 0x5e, 0x6d, 0x6d, 0xad, 0x65, 0x1e, 0x6e, 0x93, 0xf9, 0x2c,
	0x6f, 0xd0, 0xcf, 0x05, 0x26, 0xf5, 0xa0, 0xe5, 0x5a, 0x4d, 0x39, 0xca, 0x7c, 0x79, 0x88, 0xc2,
	0xf8, 0x2b, 0x81, 0xad, 0x73, 0xcf, 0x85, 0x32, 0x35, 0x7d, 0x01, 0xd9, 0x25, 0xa2, 0x1b, 0x90,
	0x11, 0x39, 0xda, 0x29, 0x0e, 0xd9, 0x5f, 0x71, 0x58, 0x72, 0xb3, 0xb7, 0x88, 0xae, 0x0c, 0x81,
	0xe1, 0x27, 0xc8, 0xba, 0x1b, 0xbd, 0x0f, 0x99, 0xe1, 0xd7, 0x32, 0x3c, 0xb0, 0x7d, 0xb2, 0xfd,
	0xfd, 0xe7, 0x8f, 0x8d, 0xcc, 0xf7, 0x46, 0xa4, 0x0c, 0x63, 0x9a, 0xc3, 0x66, 0x7c, 0x6c, 0xd0,
	0x0b, 0x1b, 0x0e, 0x58, 0x64, 0x66, 0x4b, 0x66, 0x76, 0x16, 0x98, 0xcb, 0x64, 0x1b, 0x7f, 0x26,
	0xd0, 0x7f, 0xaf, 0xea, 0x4b, 0x6c, 0x50, 0xba, 0xd3, 0x30, 0xa3, 0xcf, 0x61, 0x5f, 0x58, 0xad,
	0xa5, 0x40, 0xeb, 0x2b, 0xa1, 0xe7, 0x0d, 0x4a, 0xbf, 0xbe, 0x70, 0xef, 0xb7, 0xe7, 0x34, 0x5a,
	0xe8, 0x33, 0xd8, 0xe7, 0x42, 0xc8, 0xa6, 0xa9, 0xd0, 0x5e, 0x49, 0x53, 0xcd, 0x94, 0x96, 0x81,
	0xe3, 0x8f, 0x5c, 0x3f, 0x7a, 0xce, 0x3b, 0xcb, 0x6b, 0xa5, 0xe5, 0xf8, 0x1b, 0x81, 0xdd, 0x0b,
	0xe5, 0xae, 0x94, 0xf9, 0xcf, 0xfd, 0xc7, 0x40, 0x6f, 0x72, 0xd2, 0x4c, 0x9d, 0x55, 0x06, 0xd7,
	0x01, 0x6e, 0x1e, 0x7f, 0x95, 0x3c, 0xf4, 0x31, 0xf4, 0xc3, 0xc7, 0xaf, 0xd4, 0xb4, 0x7a, 0x52,
	0x1c, 0x4f, 0x14, 0x0e, 0x36, 0x46, 0xe4, 0xe8, 0x76, 0x79, 0x27, 0x8c, 0xdf, 0x4d, 0xe3, 0x70,
	0x5c, 0x43, 0xff, 0xe5, 0xc2, 0xf0, 0x6b, 0x25, 0x3e, 0x62, 0x82, 0x3d, 0x84, 0x2d, 0xad, 0x26,
	0x9e, 0xfb, 0xc5, 0x3a, 0xe2, 0x52, 0xf9, 0xf7, 0xdf, 0x22, 0x80, 0x76, 0x25, 0x90, 0x67, 0xb1,
	0x80, 0x69, 0xd7, 0x07, 0xd8, 0x5d, 0xad, 0x65, 0x6a, 0xd1, 0x83, 0xd4, 0x22, 0xee, 0x54, 0x57,
	0x9e, 0xae, 0xbd, 0xec, 0x8d, 0x77, 0x22, 0x65, 0x4f, 0xa0, 0x03, 0xba, 0xf5, 0x85, 0xf4, 0xf6,
	0x48, 0xb9, 0x53, 0xaf, 0x08, 0xd9, 0x45, 0xaf, 0x2d, 0x26, 0x9b, 0x81, 0xe1, 0xe9, 0xaf, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x3b, 0xe6, 0xb2, 0xaa, 0x3e, 0x03, 0x00, 0x00,
}
