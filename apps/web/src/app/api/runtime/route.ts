export const dynamic = "force-dynamic";

export function GET() {
  return Response.json({
    wsOrigin: process.env.PUBLIC_API_WS_ORIGIN ?? "",
  });
}
