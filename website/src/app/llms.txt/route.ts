import { buildLlmsTxt, TEXT_HEADERS } from '@/lib/llms';

export const dynamic = 'force-static';

export function GET(): Response {
  return new Response(buildLlmsTxt(), { headers: TEXT_HEADERS });
}
