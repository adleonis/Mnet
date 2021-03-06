# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protos/Mnet_sync.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='protos/Mnet_sync.proto',
  package='Mnetsync',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x16protos/Mnet_sync.proto\x12\x08Mnetsync\"\x83\x01\n\rAccountUpdate\x12$\n\x05Owner\x18\x01 \x01(\x0b\x32\x15.Mnetsync.AccountInfo\x12&\n\tFromState\x18\x02 \x01(\x0b\x32\x13.Mnetsync.LumpState\x12$\n\x07ToState\x18\x03 \x01(\x0b\x32\x13.Mnetsync.LumpState\"8\n\tLumpState\x12+\n\x0c\x41\x63\x63ountState\x18\x01 \x03(\x0b\x32\x15.Mnetsync.AccountInfo\"h\n\x12TransactionRequest\x12,\n\x0bTransaction\x18\x01 \x01(\x0b\x32\x17.Mnetsync.AccountUpdate\x12\x11\n\tSignature\x18\x02 \x01(\x0c\x12\x11\n\tTimestamp\x18\x03 \x01(\x05\"\x9e\x01\n\x17TransactionConfirmation\x12@\n\x1aOriginalTransactionRequest\x18\x01 \x01(\x0b\x32\x1c.Mnetsync.TransactionRequest\x12\x15\n\rCurrentStatus\x18\x02 \x01(\x08\x12*\n\x0ePeersConfirmed\x18\x03 \x03(\x0b\x32\x12.Mnetsync.PeerInfo\"G\n\x11TransactionStatus\x12\x0e\n\x06Status\x18\x01 \x01(\t\x12\x11\n\tTimestamp\x18\x02 \x01(\x05\x12\x0f\n\x07\x44\x65tails\x18\x03 \x01(\t\"\x1d\n\nPeerDemand\x12\x0f\n\x07HowMany\x18\x01 \x01(\x05\"S\n\x08PeerInfo\x12\x0c\n\x04Ipv4\x18\x01 \x01(\t\x12\x0c\n\x04Ipv6\x18\x02 \x01(\t\x12\x0c\n\x04Mdns\x18\x03 \x01(\t\x12\x0c\n\x04Port\x18\x04 \x01(\x05\x12\x0f\n\x07\x41\x64\x64ress\x18\x05 \x01(\t\"7\n\x0fTrustedPeerList\x12$\n\x08PeerList\x18\x01 \x03(\x0b\x32\x12.Mnetsync.PeerInfo\"R\n\x0b\x41\x63\x63ountInfo\x12\x16\n\x0e\x41\x63\x63ountAddress\x18\x01 \x01(\t\x12\x16\n\x0e\x41\x63\x63ountBalance\x18\x02 \x01(\x05\x12\x13\n\x0bTextMessage\x18\x03 \x01(\t\"\'\n\rAccountDemand\x12\x16\n\x0e\x41\x63\x63ountAddress\x18\x01 \x01(\t\"C\n\nCryptoMeta\x12\x11\n\tAlgorithm\x18\x01 \x01(\t\x12\x10\n\x08\x41lgoType\x18\x02 \x01(\t\x12\x10\n\x08\x45ncoding\x18\x03 \x01(\t2\xc0\x02\n\x08Mnetsync\x12=\n\x08GetPeers\x12\x14.Mnetsync.PeerDemand\x1a\x19.Mnetsync.TrustedPeerList\"\x00\x12\x42\n\x0eGetAccountInfo\x12\x17.Mnetsync.AccountDemand\x1a\x15.Mnetsync.AccountInfo\"\x00\x12S\n\x12ProcessTransaction\x12\x1c.Mnetsync.TransactionRequest\x1a\x1b.Mnetsync.TransactionStatus\"\x00\x30\x01\x12\\\n\x12\x43onfirmTransaction\x12!.Mnetsync.TransactionConfirmation\x1a!.Mnetsync.TransactionConfirmation\"\x00\x62\x06proto3')
)




_ACCOUNTUPDATE = _descriptor.Descriptor(
  name='AccountUpdate',
  full_name='Mnetsync.AccountUpdate',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Owner', full_name='Mnetsync.AccountUpdate.Owner', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='FromState', full_name='Mnetsync.AccountUpdate.FromState', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ToState', full_name='Mnetsync.AccountUpdate.ToState', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=37,
  serialized_end=168,
)


_LUMPSTATE = _descriptor.Descriptor(
  name='LumpState',
  full_name='Mnetsync.LumpState',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='AccountState', full_name='Mnetsync.LumpState.AccountState', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=170,
  serialized_end=226,
)


_TRANSACTIONREQUEST = _descriptor.Descriptor(
  name='TransactionRequest',
  full_name='Mnetsync.TransactionRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Transaction', full_name='Mnetsync.TransactionRequest.Transaction', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Signature', full_name='Mnetsync.TransactionRequest.Signature', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Timestamp', full_name='Mnetsync.TransactionRequest.Timestamp', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=228,
  serialized_end=332,
)


_TRANSACTIONCONFIRMATION = _descriptor.Descriptor(
  name='TransactionConfirmation',
  full_name='Mnetsync.TransactionConfirmation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='OriginalTransactionRequest', full_name='Mnetsync.TransactionConfirmation.OriginalTransactionRequest', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='CurrentStatus', full_name='Mnetsync.TransactionConfirmation.CurrentStatus', index=1,
      number=2, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='PeersConfirmed', full_name='Mnetsync.TransactionConfirmation.PeersConfirmed', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=335,
  serialized_end=493,
)


_TRANSACTIONSTATUS = _descriptor.Descriptor(
  name='TransactionStatus',
  full_name='Mnetsync.TransactionStatus',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Status', full_name='Mnetsync.TransactionStatus.Status', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Timestamp', full_name='Mnetsync.TransactionStatus.Timestamp', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Details', full_name='Mnetsync.TransactionStatus.Details', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=495,
  serialized_end=566,
)


_PEERDEMAND = _descriptor.Descriptor(
  name='PeerDemand',
  full_name='Mnetsync.PeerDemand',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='HowMany', full_name='Mnetsync.PeerDemand.HowMany', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=568,
  serialized_end=597,
)


_PEERINFO = _descriptor.Descriptor(
  name='PeerInfo',
  full_name='Mnetsync.PeerInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Ipv4', full_name='Mnetsync.PeerInfo.Ipv4', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Ipv6', full_name='Mnetsync.PeerInfo.Ipv6', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Mdns', full_name='Mnetsync.PeerInfo.Mdns', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Port', full_name='Mnetsync.PeerInfo.Port', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Address', full_name='Mnetsync.PeerInfo.Address', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=599,
  serialized_end=682,
)


_TRUSTEDPEERLIST = _descriptor.Descriptor(
  name='TrustedPeerList',
  full_name='Mnetsync.TrustedPeerList',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='PeerList', full_name='Mnetsync.TrustedPeerList.PeerList', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=684,
  serialized_end=739,
)


_ACCOUNTINFO = _descriptor.Descriptor(
  name='AccountInfo',
  full_name='Mnetsync.AccountInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='AccountAddress', full_name='Mnetsync.AccountInfo.AccountAddress', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='AccountBalance', full_name='Mnetsync.AccountInfo.AccountBalance', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='TextMessage', full_name='Mnetsync.AccountInfo.TextMessage', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=741,
  serialized_end=823,
)


_ACCOUNTDEMAND = _descriptor.Descriptor(
  name='AccountDemand',
  full_name='Mnetsync.AccountDemand',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='AccountAddress', full_name='Mnetsync.AccountDemand.AccountAddress', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=825,
  serialized_end=864,
)


_CRYPTOMETA = _descriptor.Descriptor(
  name='CryptoMeta',
  full_name='Mnetsync.CryptoMeta',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='Algorithm', full_name='Mnetsync.CryptoMeta.Algorithm', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='AlgoType', full_name='Mnetsync.CryptoMeta.AlgoType', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='Encoding', full_name='Mnetsync.CryptoMeta.Encoding', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=866,
  serialized_end=933,
)

_ACCOUNTUPDATE.fields_by_name['Owner'].message_type = _ACCOUNTINFO
_ACCOUNTUPDATE.fields_by_name['FromState'].message_type = _LUMPSTATE
_ACCOUNTUPDATE.fields_by_name['ToState'].message_type = _LUMPSTATE
_LUMPSTATE.fields_by_name['AccountState'].message_type = _ACCOUNTINFO
_TRANSACTIONREQUEST.fields_by_name['Transaction'].message_type = _ACCOUNTUPDATE
_TRANSACTIONCONFIRMATION.fields_by_name['OriginalTransactionRequest'].message_type = _TRANSACTIONREQUEST
_TRANSACTIONCONFIRMATION.fields_by_name['PeersConfirmed'].message_type = _PEERINFO
_TRUSTEDPEERLIST.fields_by_name['PeerList'].message_type = _PEERINFO
DESCRIPTOR.message_types_by_name['AccountUpdate'] = _ACCOUNTUPDATE
DESCRIPTOR.message_types_by_name['LumpState'] = _LUMPSTATE
DESCRIPTOR.message_types_by_name['TransactionRequest'] = _TRANSACTIONREQUEST
DESCRIPTOR.message_types_by_name['TransactionConfirmation'] = _TRANSACTIONCONFIRMATION
DESCRIPTOR.message_types_by_name['TransactionStatus'] = _TRANSACTIONSTATUS
DESCRIPTOR.message_types_by_name['PeerDemand'] = _PEERDEMAND
DESCRIPTOR.message_types_by_name['PeerInfo'] = _PEERINFO
DESCRIPTOR.message_types_by_name['TrustedPeerList'] = _TRUSTEDPEERLIST
DESCRIPTOR.message_types_by_name['AccountInfo'] = _ACCOUNTINFO
DESCRIPTOR.message_types_by_name['AccountDemand'] = _ACCOUNTDEMAND
DESCRIPTOR.message_types_by_name['CryptoMeta'] = _CRYPTOMETA
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AccountUpdate = _reflection.GeneratedProtocolMessageType('AccountUpdate', (_message.Message,), dict(
  DESCRIPTOR = _ACCOUNTUPDATE,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.AccountUpdate)
  ))
_sym_db.RegisterMessage(AccountUpdate)

LumpState = _reflection.GeneratedProtocolMessageType('LumpState', (_message.Message,), dict(
  DESCRIPTOR = _LUMPSTATE,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.LumpState)
  ))
_sym_db.RegisterMessage(LumpState)

TransactionRequest = _reflection.GeneratedProtocolMessageType('TransactionRequest', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTIONREQUEST,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.TransactionRequest)
  ))
_sym_db.RegisterMessage(TransactionRequest)

TransactionConfirmation = _reflection.GeneratedProtocolMessageType('TransactionConfirmation', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTIONCONFIRMATION,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.TransactionConfirmation)
  ))
_sym_db.RegisterMessage(TransactionConfirmation)

TransactionStatus = _reflection.GeneratedProtocolMessageType('TransactionStatus', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTIONSTATUS,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.TransactionStatus)
  ))
_sym_db.RegisterMessage(TransactionStatus)

PeerDemand = _reflection.GeneratedProtocolMessageType('PeerDemand', (_message.Message,), dict(
  DESCRIPTOR = _PEERDEMAND,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.PeerDemand)
  ))
_sym_db.RegisterMessage(PeerDemand)

PeerInfo = _reflection.GeneratedProtocolMessageType('PeerInfo', (_message.Message,), dict(
  DESCRIPTOR = _PEERINFO,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.PeerInfo)
  ))
_sym_db.RegisterMessage(PeerInfo)

TrustedPeerList = _reflection.GeneratedProtocolMessageType('TrustedPeerList', (_message.Message,), dict(
  DESCRIPTOR = _TRUSTEDPEERLIST,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.TrustedPeerList)
  ))
_sym_db.RegisterMessage(TrustedPeerList)

AccountInfo = _reflection.GeneratedProtocolMessageType('AccountInfo', (_message.Message,), dict(
  DESCRIPTOR = _ACCOUNTINFO,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.AccountInfo)
  ))
_sym_db.RegisterMessage(AccountInfo)

AccountDemand = _reflection.GeneratedProtocolMessageType('AccountDemand', (_message.Message,), dict(
  DESCRIPTOR = _ACCOUNTDEMAND,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.AccountDemand)
  ))
_sym_db.RegisterMessage(AccountDemand)

CryptoMeta = _reflection.GeneratedProtocolMessageType('CryptoMeta', (_message.Message,), dict(
  DESCRIPTOR = _CRYPTOMETA,
  __module__ = 'protos.Mnet_sync_pb2'
  # @@protoc_insertion_point(class_scope:Mnetsync.CryptoMeta)
  ))
_sym_db.RegisterMessage(CryptoMeta)



_MNETSYNC = _descriptor.ServiceDescriptor(
  name='Mnetsync',
  full_name='Mnetsync.Mnetsync',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=936,
  serialized_end=1256,
  methods=[
  _descriptor.MethodDescriptor(
    name='GetPeers',
    full_name='Mnetsync.Mnetsync.GetPeers',
    index=0,
    containing_service=None,
    input_type=_PEERDEMAND,
    output_type=_TRUSTEDPEERLIST,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='GetAccountInfo',
    full_name='Mnetsync.Mnetsync.GetAccountInfo',
    index=1,
    containing_service=None,
    input_type=_ACCOUNTDEMAND,
    output_type=_ACCOUNTINFO,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='ProcessTransaction',
    full_name='Mnetsync.Mnetsync.ProcessTransaction',
    index=2,
    containing_service=None,
    input_type=_TRANSACTIONREQUEST,
    output_type=_TRANSACTIONSTATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='ConfirmTransaction',
    full_name='Mnetsync.Mnetsync.ConfirmTransaction',
    index=3,
    containing_service=None,
    input_type=_TRANSACTIONCONFIRMATION,
    output_type=_TRANSACTIONCONFIRMATION,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_MNETSYNC)

DESCRIPTOR.services_by_name['Mnetsync'] = _MNETSYNC

# @@protoc_insertion_point(module_scope)
