// routes/print-order-by-id.js
import fetch from 'node-fetch';

// VARS de ambiente (configure no Koyeb)
const PRINT_AGENT_URL   = process.env.PRINT_AGENT_URL;      // ex: https://seu-tunel.trycloudflare.com/print
const PRINT_AGENT_TOKEN = process.env.PRINT_AGENT_TOKEN;    // o mesmo TOKEN configurado no agent.py

// Funções utilitárias — ajuste para sua camada de dados
async function getOrderById(id) {
  // TODO: troque por consulta real no seu DB
  // Deve retornar { id, created_at, customer_name, phone, address, payment_method, notes, items: [{qty, item_name, price}], subtotal, delivery_fee, total, status }
  throw new Error('implementar getOrderById(id)');
}

function toAgentPayload(o) {
  return {
    id: o.id,
    dataHora: new Date(o.created_at).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
    cliente:  o.customer_name || '',
    telefone: (o.phone || '').replace(/\D+/g, '').slice(0, 11),
    endereco: o.address || '',
    complemento: '', // preencha se tiver
    pagamento: o.payment_method || '',
    itens: (o.items || []).map(i => ({
      qtd: Number(i.qty),
      nome: i.item_name,
      // no cupom você imprimia "qtd x nome  R$ valorLinha"
      // aqui já mandamos o valor da LINHA (qty * price)
      preco: Number(i.price) * Number(i.qty)
    })),
    subtotal: Number(o.subtotal || 0),
    entrega:  Number(o.delivery_fee || 0),
    total:    Number(o.total || 0),
    status:   o.status || 'Em preparo'
  };
}

export async function printOrderById(req, res) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('ID inválido');

    if (!PRINT_AGENT_URL || !PRINT_AGENT_TOKEN) {
      return res.status(500).send('PRINT_AGENT_URL/TOKEN não configurados');
    }

    const o = await getOrderById(id);

    // idempotência (evita impressão duplicada em retry)
    const idemKey = String(id);

    const payload = { type: 'DELIVERY_ORDER', payload: toAgentPayload(o) };
    const resp = await fetch(PRINT_AGENT_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth': PRINT_AGENT_TOKEN,
        'X-Idempotency-Key': idemKey
      },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const txt = await resp.text().catch(()=> '');
      return res.status(502).send(`Falha no agente: ${resp.status} ${txt}`);
    }

    // (Opcional) notificar a loja via socket.io que imprimiu
    // req.io?.emit('printed', { orderId: id });

    return res.json({ ok: true });
  } catch (e) {
    console.error('[printOrderById]', e);
    return res.status(500).send('Erro interno ao imprimir');
  }
}
