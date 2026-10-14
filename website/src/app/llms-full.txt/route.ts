import { buildLlmsFullTxt, TEXT_HEADERS } from '@/lib/llms';

export const dynamic = 'force-static';

export function GET(): Response {
  return new Response(buildLlmsFullTxt(), { headers: TEXT_HEADERS });
}
