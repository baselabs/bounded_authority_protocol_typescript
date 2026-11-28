// Every runtime-neutral conformance core, in a stable order. Each lane runs all of them.
import type { Core } from "./types.js";
import { core as v1 } from "./v1.js";
import { core as v2 } from "./v2.js";
import { core as v3 } from "./v3.js";
import { core as localLoopbackHttp } from "./local_loopback_http.js";
import { core as roleAttestation } from "./role_attestation.js";
import { core as contentAssertion } from "./content_assertion.js";
import { core as strictEd25519, stringOrUri } from "./strict_ed25519.js";
import { core as producerCanonicality } from "./producer_canonicality.js";
import { core as selectorFloatZero } from "./selector_float_zero.js";

import { core as contentAssertionEs256 } from "./content_assertion_es256.js";
import { core as actionApproval } from "./action_approval.js";

export const CORES: readonly Core[] = [v1, v2, v3, localLoopbackHttp, roleAttestation, contentAssertion, strictEd25519, stringOrUri, producerCanonicality, selectorFloatZero, contentAssertionEs256, actionApproval];
