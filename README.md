# ConvertFin — Conversor de Extratos Bancários

## Como rodar localmente

```bash
pip install -r requirements.txt
python app.py
```

Acesse: http://localhost:5000

**Admin padrão:** admin@convertfin.com.br / admin123
**Admin URL:** seudominio.com/admin (não aparece na navegação)

---

## Deploy no Render

### Passo 1 — Repositório GitHub
Crie um repositório **privado** e suba todos os arquivos diretamente na **raiz** do repositório (não dentro de pasta). A estrutura deve ser:
```
/ (raiz do repositório)
├── app.py
├── requirements.txt
├── Procfile
└── templates/
```

### Passo 2 — Criar Web Service no Render
- https://render.com → New → Web Service
- Conecte o repositório
- Configure:
  - **Runtime:** Python 3
  - **Build Command:** `pip install -r requirements.txt`
  - **Start Command:** `python -m gunicorn app:app`
  - **Instance Type:** Free

> ⚠️ Use `python -m gunicorn app:app` e não apenas `gunicorn app:app`.
> Isso corrige o erro "gunicorn: command not found" no Render.

### Passo 3 — Variáveis de ambiente
No painel do Render → Environment → Add Environment Variable:

| Variável | Valor |
|---|---|
| `SECRET_KEY` | qualquer string aleatória longa |
| `WEBHOOK_TOKEN` | outra string secreta (para webhook de pagamento) |
| `ANTHROPIC_API_KEY` | sua chave Anthropic (só quando for ativar a IA) |

### Passo 4 — Deploy
Clique em Deploy. Em 2-3 minutos o app estará no ar.

---

## Pagamento (Stripe)

O link de checkout do Stripe já está embutido em `templates/assinar.html`.

Para receber confirmação automática de pagamento e ativar o plano Pro do usuário, configure o webhook do Stripe:

1. No painel Stripe → Developers → Webhooks → Add endpoint
2. URL: `https://seudominio.com/webhook/pagamento`
3. Evento: `checkout.session.completed`
4. No body, o Stripe deve enviar o e-mail do cliente e o `WEBHOOK_TOKEN`

**Formato esperado pelo webhook:**
```json
{ "email": "usuario@email.com", "token": "SEU_WEBHOOK_TOKEN" }
```

---

## Acessar o Admin

O painel admin **não aparece na navegação** por segurança. Acesse diretamente:
```
https://seudominio.com/admin
```
Só funciona se você estiver logado com uma conta admin.

---

## Ativar IA

Quando tiver assinantes suficientes:
1. Configure `ANTHROPIC_API_KEY` no Render
2. Acesse /admin → aba Configurações
3. Ligue o toggle "Categorização com IA"
4. O recurso aparece automaticamente para usuários Pro

---

## Melhorias sugeridas para o futuro

- [ ] Recuperação de senha por e-mail (requer SendGrid ou similar)
- [ ] Migrar SQLite → PostgreSQL para produção (Render oferece grátis)
- [ ] Suporte a extrato escaneado (OCR via Tesseract)
- [ ] Conversão em lote (vários PDFs de uma vez)
- [ ] Webhook Stripe nativo com validação de assinatura
