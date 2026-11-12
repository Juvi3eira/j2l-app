// J2L Financas e Consignado: criacao de acessos dentro do app (Etapa C).
// Funcao Edge do Supabase. So quem tem perfil master pode chamar.
// Ela convida a pessoa por e-mail (a pessoa define a propria senha pelo link)
// e grava o profile correspondente (role store com store_id, ou role master).
// Deploy: painel do Supabase, Edge Functions, nome "create-user".
// As variaveis SUPABASE_URL, SUPABASE_ANON_KEY e SUPABASE_SERVICE_ROLE_KEY
// sao injetadas automaticamente pelo runtime do Supabase.

import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const APP_URL = "https://j2l.pages.dev";

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return json({ ok: false, error: "Metodo nao permitido. Use POST." }, 405);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  if (!supabaseUrl || !anonKey || !serviceKey) {
    return json({ ok: false, error: "Ambiente da funcao incompleto." }, 500);
  }

  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader) {
    return json({ ok: false, error: "Falta o cabecalho de autenticacao." }, 401);
  }
  const caller = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: userData, error: userErr } = await caller.auth.getUser();
  if (userErr || !userData || !userData.user) {
    return json({ ok: false, error: "Nao autenticado." }, 401);
  }

  const admin = createClient(supabaseUrl, serviceKey);
  const { data: prof, error: profErr } = await admin
    .from("profiles")
    .select("role")
    .eq("id", userData.user.id)
    .single();
  if (profErr || !prof || prof.role !== "master") {
    return json({ ok: false, error: "Apenas masters podem criar acessos." }, 403);
  }

  let body;
  try {
    body = await req.json();
  } catch (e) {
    return json({ ok: false, error: "Corpo do pedido invalido (JSON esperado)." }, 400);
  }
  const email = String((body && body.email) ?? "").trim();
  const role = body ? body.role : null;
  const displayName = String((body && body.display_name) ?? "").trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ ok: false, error: "E-mail invalido." }, 400);
  }
  if (role !== "store" && role !== "master") {
    return json({ ok: false, error: "Role invalido. Use store ou master." }, 400);
  }
  let storeId = null;
  if (role === "store") {
    storeId = Number(body.store_id);
    if (!storeId || !Number.isFinite(storeId)) {
      return json({ ok: false, error: "store_id e obrigatorio para acessos de loja." }, 400);
    }
    const { data: store, error: storeErr } = await admin
      .from("stores")
      .select("id")
      .eq("id", storeId)
      .single();
    if (storeErr || !store) {
      return json({ ok: false, error: "Loja nao encontrada para o store_id informado." }, 400);
    }
  }

  const { data: invited, error: invErr } = await admin.auth.admin.inviteUserByEmail(email, {
    redirectTo: APP_URL,
    data: displayName ? { display_name: displayName } : undefined,
  });
  if (invErr || !invited || !invited.user) {
    return json({ ok: false, error: "Falha ao enviar o convite: " + (invErr ? invErr.message : "resposta vazia") }, 400);
  }
  const userId = invited.user.id;

  const { error: insErr } = await admin.from("profiles").insert({
    id: userId,
    role: role,
    store_id: storeId,
    display_name: displayName,
  });
  if (insErr) {
    return json({
      ok: false,
      error: "Convite enviado, mas o perfil nao foi salvo: " + insErr.message,
      user_id: userId,
    }, 500);
  }

  return json({ ok: true, user_id: userId });
});
