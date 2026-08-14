#include <linep_sl/sl2.hpp>

namespace linep::sl {

bool validate_peer_identity(const PeerIdentity& peer) noexcept {
    if (peer.trust_domain_id == 0 || peer.node_id == 0) {
        return false;
    }
    return true;
}

} // namespace linep::sl
