package internal

import (
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// ContractRegistry returns the typed contract descriptors for every module
// and step served by this plugin. The workflow engine calls this via the
// sdk.ContractProvider interface to decode typed configs from YAML into the
// correct proto message before dispatching CreateTypedModule / CreateTypedStep.
//
// Without this method the engine has TypedModuleProvider/TypedStepProvider
// registration but no proto descriptor map, so it passes nil config and the
// plugin fails validation at module Init / step Execute time (Bug 3).
func (p *AuditChainPlugin) ContractRegistry() *pb.ContractRegistry {
	return auditContractRegistry
}

// auditContractRegistry advertises STRICT_PROTO contracts for every typed
// module and step. The FileDescriptorSet includes google.protobuf.Empty
// (used as the step config message for stateless steps) and the generated
// audit proto file so the engine can resolve every Config/Input/Output
// message by full name.
var auditContractRegistry = &pb.ContractRegistry{
	FileDescriptorSet: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(structpb.File_google_protobuf_struct_proto),
			protodesc.ToFileDescriptorProto(emptypb.File_google_protobuf_empty_proto),
			protodesc.ToFileDescriptorProto(auditv1.File_audit_proto),
		},
	},
	Contracts: []*pb.ContractDescriptor{
		// ── modules ──────────────────────────────────────────────────────────
		moduleContract("audit.ledger", "LedgerConfig"),
		moduleContract("audit.anchor_provider.opentimestamps", "OpenTimestampsProviderConfig"),
		moduleContract("audit.anchor_provider.git", "GitAnchorProviderConfig"),
		moduleContract("audit.anchor_provider.sigstore", "SigstoreProviderConfig"),

		// ── steps ────────────────────────────────────────────────────────────
		// Most audit-chain steps are stateless: config is google.protobuf.Empty.
		// poll_anchor_confirmation and public_receipt declare typed config
		// messages so BMW-style YAML `config:` blocks pass STRICT_PROTO
		// validation (v0.2.2 — fix for BMW smoke against workflow v0.51.5).
		stepContractEmptyConfig("step.audit.append", "AppendRequest", "AppendResponse"),
		stepContractEmptyConfig("step.audit.verify", "VerifyRequest", "VerifyResponse"),
		stepContractEmptyConfig("step.audit.merkle_root", "MerkleRootRequest", "MerkleRootResponse"),
		stepContractEmptyConfig("step.audit.anchor", "AnchorRequest", "AnchorResponse"),
		stepContractTypedConfig("step.audit.poll_anchor_confirmation", "PollAnchorConfirmationConfig", "PollAnchorConfirmationRequest", "PollAnchorConfirmationResponse"),
		stepContractEmptyConfig("step.audit.proof", "ProofRequest", "ProofResponse"),
		stepContractTypedConfig("step.audit.public_receipt", "PublicReceiptConfig", "PublicReceiptRequest", "PublicReceiptResponse"),
	},
}

// auditProtoPkg is the proto package for all audit-chain typed messages.
const auditProtoPkg = "workflow.plugin.audit.v1."

// moduleContract builds a STRICT_PROTO module contract descriptor pointing
// at a message in the audit proto package.
func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: auditProtoPkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

// stepContractEmptyConfig builds a STRICT_PROTO step contract descriptor for
// steps that take no config (config message = google.protobuf.Empty). Input
// and output messages live in the audit proto package.
func stepContractEmptyConfig(stepType, inputMessage, outputMessage string) *pb.ContractDescriptor {
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: "google.protobuf.Empty",
		InputMessage:  auditProtoPkg + inputMessage,
		OutputMessage: auditProtoPkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

// stepContractTypedConfig builds a STRICT_PROTO step contract descriptor for
// steps whose YAML `config:` block carries typed fields (BMW-style usage where
// the engine validates every key in `config:` against the proto message under
// DiscardUnknown=false). All three messages live in the audit proto package.
func stepContractTypedConfig(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: auditProtoPkg + configMessage,
		InputMessage:  auditProtoPkg + inputMessage,
		OutputMessage: auditProtoPkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
