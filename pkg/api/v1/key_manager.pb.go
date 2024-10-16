// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        (unknown)
// source: key_manager.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GenerateKeyPairRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Password to encrypt the private key
	// This will be only used if the keystore is local filesystem based
	Password string `protobuf:"bytes,1,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *GenerateKeyPairRequest) Reset() {
	*x = GenerateKeyPairRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateKeyPairRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateKeyPairRequest) ProtoMessage() {}

func (x *GenerateKeyPairRequest) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateKeyPairRequest.ProtoReflect.Descriptor instead.
func (*GenerateKeyPairRequest) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{0}
}

func (x *GenerateKeyPairRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type GenerateKeyPairResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Public key hex of the generated keypair
	PublicKey string `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// Private key hex of the generated keypair
	PrivateKey string `protobuf:"bytes,2,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// Mnemonic of the generated keypair
	Mnemonic string `protobuf:"bytes,3,opt,name=mnemonic,proto3" json:"mnemonic,omitempty"`
}

func (x *GenerateKeyPairResponse) Reset() {
	*x = GenerateKeyPairResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateKeyPairResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateKeyPairResponse) ProtoMessage() {}

func (x *GenerateKeyPairResponse) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateKeyPairResponse.ProtoReflect.Descriptor instead.
func (*GenerateKeyPairResponse) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{1}
}

func (x *GenerateKeyPairResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

func (x *GenerateKeyPairResponse) GetPrivateKey() string {
	if x != nil {
		return x.PrivateKey
	}
	return ""
}

func (x *GenerateKeyPairResponse) GetMnemonic() string {
	if x != nil {
		return x.Mnemonic
	}
	return ""
}

type ImportKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Plaintext hex private key of the keypair or BigInteger
	PrivateKey string `protobuf:"bytes,1,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// Mnemonic of the keypair to import. One of private_key or mnemonic should be provided
	Mnemonic string `protobuf:"bytes,2,opt,name=mnemonic,proto3" json:"mnemonic,omitempty"`
	// Password to encrypt the private key
	Password string `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *ImportKeyRequest) Reset() {
	*x = ImportKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImportKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImportKeyRequest) ProtoMessage() {}

func (x *ImportKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImportKeyRequest.ProtoReflect.Descriptor instead.
func (*ImportKeyRequest) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{2}
}

func (x *ImportKeyRequest) GetPrivateKey() string {
	if x != nil {
		return x.PrivateKey
	}
	return ""
}

func (x *ImportKeyRequest) GetMnemonic() string {
	if x != nil {
		return x.Mnemonic
	}
	return ""
}

func (x *ImportKeyRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type ImportKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Public key hex of the imported keypair
	PublicKey string `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *ImportKeyResponse) Reset() {
	*x = ImportKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImportKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImportKeyResponse) ProtoMessage() {}

func (x *ImportKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImportKeyResponse.ProtoReflect.Descriptor instead.
func (*ImportKeyResponse) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{3}
}

func (x *ImportKeyResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type ListKeysRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ListKeysRequest) Reset() {
	*x = ListKeysRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListKeysRequest) ProtoMessage() {}

func (x *ListKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListKeysRequest.ProtoReflect.Descriptor instead.
func (*ListKeysRequest) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{4}
}

type ListKeysResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// List of public keys
	PublicKeys []string `protobuf:"bytes,1,rep,name=public_keys,json=publicKeys,proto3" json:"public_keys,omitempty"`
}

func (x *ListKeysResponse) Reset() {
	*x = ListKeysResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_key_manager_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListKeysResponse) ProtoMessage() {}

func (x *ListKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_key_manager_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListKeysResponse.ProtoReflect.Descriptor instead.
func (*ListKeysResponse) Descriptor() ([]byte, []int) {
	return file_key_manager_proto_rawDescGZIP(), []int{5}
}

func (x *ListKeysResponse) GetPublicKeys() []string {
	if x != nil {
		return x.PublicKeys
	}
	return nil
}

var File_key_manager_proto protoreflect.FileDescriptor

var file_key_manager_proto_rawDesc = []byte{
	0x0a, 0x11, 0x6b, 0x65, 0x79, 0x5f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6b, 0x65, 0x79, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e,
	0x76, 0x31, 0x22, 0x34, 0x0a, 0x16, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08,
	0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x75, 0x0a, 0x17, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x4b, 0x65, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x22,
	0x6b, 0x0a, 0x10, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63,
	0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x32, 0x0a, 0x11,
	0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79,
	0x22, 0x11, 0x0a, 0x0f, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x33, 0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x73, 0x32, 0x91, 0x02, 0x0a, 0x0a, 0x4b, 0x65, 0x79,
	0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x62, 0x0a, 0x0f, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72, 0x12, 0x25, 0x2e, 0x6b, 0x65, 0x79,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x26, 0x2e, 0x6b, 0x65, 0x79, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69,
	0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x50, 0x0a, 0x09, 0x49,
	0x6d, 0x70, 0x6f, 0x72, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x1f, 0x2e, 0x6b, 0x65, 0x79, 0x6d, 0x61,
	0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e, 0x6b, 0x65, 0x79, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74,
	0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4d, 0x0a,
	0x08, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x1e, 0x2e, 0x6b, 0x65, 0x79, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65,
	0x79, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6b, 0x65, 0x79, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65,
	0x79, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x2e, 0x5a, 0x2c,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x61, 0x79, 0x72, 0x2d,
	0x6c, 0x61, 0x62, 0x73, 0x2f, 0x63, 0x65, 0x72, 0x62, 0x65, 0x72, 0x75, 0x73, 0x2d, 0x61, 0x70,
	0x69, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_key_manager_proto_rawDescOnce sync.Once
	file_key_manager_proto_rawDescData = file_key_manager_proto_rawDesc
)

func file_key_manager_proto_rawDescGZIP() []byte {
	file_key_manager_proto_rawDescOnce.Do(func() {
		file_key_manager_proto_rawDescData = protoimpl.X.CompressGZIP(file_key_manager_proto_rawDescData)
	})
	return file_key_manager_proto_rawDescData
}

var file_key_manager_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_key_manager_proto_goTypes = []interface{}{
	(*GenerateKeyPairRequest)(nil),  // 0: keymanager.v1.GenerateKeyPairRequest
	(*GenerateKeyPairResponse)(nil), // 1: keymanager.v1.GenerateKeyPairResponse
	(*ImportKeyRequest)(nil),        // 2: keymanager.v1.ImportKeyRequest
	(*ImportKeyResponse)(nil),       // 3: keymanager.v1.ImportKeyResponse
	(*ListKeysRequest)(nil),         // 4: keymanager.v1.ListKeysRequest
	(*ListKeysResponse)(nil),        // 5: keymanager.v1.ListKeysResponse
}
var file_key_manager_proto_depIdxs = []int32{
	0, // 0: keymanager.v1.KeyManager.GenerateKeyPair:input_type -> keymanager.v1.GenerateKeyPairRequest
	2, // 1: keymanager.v1.KeyManager.ImportKey:input_type -> keymanager.v1.ImportKeyRequest
	4, // 2: keymanager.v1.KeyManager.ListKeys:input_type -> keymanager.v1.ListKeysRequest
	1, // 3: keymanager.v1.KeyManager.GenerateKeyPair:output_type -> keymanager.v1.GenerateKeyPairResponse
	3, // 4: keymanager.v1.KeyManager.ImportKey:output_type -> keymanager.v1.ImportKeyResponse
	5, // 5: keymanager.v1.KeyManager.ListKeys:output_type -> keymanager.v1.ListKeysResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_key_manager_proto_init() }
func file_key_manager_proto_init() {
	if File_key_manager_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_key_manager_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateKeyPairRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_key_manager_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateKeyPairResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_key_manager_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImportKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_key_manager_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImportKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_key_manager_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListKeysRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_key_manager_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListKeysResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_key_manager_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_key_manager_proto_goTypes,
		DependencyIndexes: file_key_manager_proto_depIdxs,
		MessageInfos:      file_key_manager_proto_msgTypes,
	}.Build()
	File_key_manager_proto = out.File
	file_key_manager_proto_rawDesc = nil
	file_key_manager_proto_goTypes = nil
	file_key_manager_proto_depIdxs = nil
}
