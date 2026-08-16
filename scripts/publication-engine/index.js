'use strict';

/**
 * Barrel export for the Publication Engine. The DAG, in call order:
 *
 *   case (validateCase) -> decide() -> buildManifest() -> authorize()
 *     -> sink.publish() [verifyAuthorization() + disposition check + audit]
 *
 * No renderer, workflow, API endpoint, or sink may infer publication
 * permission on its own — every path to release goes through decide() and
 * a matching signed authorization. See SKILL.md for the full design.
 */

module.exports = {
  ...require('./canonical_json'),
  ...require('./case_schema'),
  ...require('./publication_engine'),
  ...require('./release_manifest'),
  ...require('./signing'),
  ...require('./authorization'),
  ...require('./nonce_store'),
  ...require('./publication_sinks'),
  ...require('./audit'),
};
