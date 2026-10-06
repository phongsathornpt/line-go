package types

// Operation and ContactRelation are the public aliases exported by LINEJS.
type Operation = Pb1C13154r6
type ContactRelation = Pb1EnumC13151r3

// SyncResponse is the success payload returned by TalkService.Sync.
type SyncResponse = Pb1X7

// MessageRelationType identifies how a message relates to another message.
type MessageRelationType = Pb1EnumC13015h6

const MessageRelationReply MessageRelationType = Pb1EnumC13015h6REPLY

// MessageServiceCode identifies the LINE service that owns a related message.
type MessageServiceCode = Pb1E7

const MessageServiceTalk MessageServiceCode = Pb1E7TALK
