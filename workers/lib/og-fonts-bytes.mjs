// ESM-only, reached exclusively via a dynamic import() from
// og-fonts-init.js's Cloudflare Workers branch — never by plain Node.
// Same reasoning as resvg-wasm-bytes.mjs: a static ESM import of a
// wrangler.jsonc `rules`-matched file (here, .woff -> Data module)
// resolves at build time; require('*.woff') from CommonJS does not get
// the same treatment and fails at runtime instead.
import interRegular from '../../api/_lib/fonts/Inter-Regular.woff';
import interBold from '../../api/_lib/fonts/Inter-Bold.woff';
import interExtraBold from '../../api/_lib/fonts/Inter-ExtraBold.woff';

export default { interRegular, interBold, interExtraBold };
