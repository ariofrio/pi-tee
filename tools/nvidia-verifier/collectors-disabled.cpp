// Verification-only client: local GPU/switch collection is never needed.
// These replace only NVIDIA's three dlopen-based collection implementations.
#include "nv_attestation/gpu/nvml_client.h"
#include "nv_attestation/gpu/corelib_client.h"
#include "nv_attestation/switch/nscq_client.h"

namespace nvattestation {
bool g_nvml_initialized = false;
bool g_corelib_initialized = false;
bool g_nscq_initialized = false;
Error init_nvml() { return Error::FeatureNotEnabled; }
Error init_corelib() { return Error::FeatureNotEnabled; }
Error init_nscq() { return Error::FeatureNotEnabled; }
void shutdown_nvml() {}
void shutdown_corelib() {}
void shutdown_nscq() {}
Error get_driver_version(std::string&) { return Error::FeatureNotEnabled; }
Error is_cc_enabled(bool&) { return Error::FeatureNotEnabled; }
Error is_ppcie_mode_enabled(bool&) { return Error::FeatureNotEnabled; }
Error collect_evidence_nvml(const std::vector<uint8_t>&, std::vector<std::shared_ptr<GpuEvidence>>&) { return Error::FeatureNotEnabled; }
Error collect_evidence_corelib(const std::vector<uint8_t>&, GpuArchitecture, std::vector<std::shared_ptr<GpuEvidence>>&) { return Error::FeatureNotEnabled; }
Error collect_evidence_nscq(const std::vector<uint8_t>&, std::vector<std::shared_ptr<SwitchEvidence>>&) { return Error::FeatureNotEnabled; }
Error get_all_switch_uuid(std::vector<std::string>&) { return Error::FeatureNotEnabled; }
Error get_switch_tnvl_status(const std::string&, SwitchTnvlMode&) { return Error::FeatureNotEnabled; }
Error get_attestation_cert_chain(const std::string&, std::string&) { return Error::FeatureNotEnabled; }
Error get_attestation_report(const std::string&, const std::vector<uint8_t>&, std::vector<uint8_t>&) { return Error::FeatureNotEnabled; }
Error get_switch_architecture(SwitchArchitecture&) { return Error::FeatureNotEnabled; }
}
