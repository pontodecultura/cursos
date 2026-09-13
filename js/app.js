import { CONFIG } from './config.js';
import { normalizePhone, applyMask } from './phone.js';
import { sha256Hex, decryptGroupLink } from './crypto.js';
import { clearSession, isRateLimited, registerAttempt } from './storage.js';

const AUTHORIZED = window.AUTHORIZED;

const els = {
  form: document.getElementById('accessForm'),
  phone: document.getElementById('phone'),
  button: document.getElementById('checkButton'),
  status: document.getElementById('status'),
  accessCard: document.getElementById('accessCard'),
  successCard: document.getElementById('successCard'),
  whatsappButton: document.getElementById('whatsappButton'),
  logoutButton: document.getElementById('logoutButton')
};

if (!AUTHORIZED?.records?.length) {
  setStatus('Banco de autorizações não encontrado.', 'error');
  els.button.disabled = true;
}

const recordsByHash = new Map(
  (AUTHORIZED?.records || []).map(record => [record.hash, record])
);

function setStatus(message = '', type = '') {
  els.status.textContent = message;
  els.status.className = type ? `status ${type}` : 'status';
}

function rememberSession(hash) {
  const expiresAt = Date.now() + (AUTHORIZED.sessionHours * 60 * 60 * 1000);
  localStorage.setItem(CONFIG.sessionKey, JSON.stringify({ hash, expiresAt }));
}

function getSession() {
  try {
    const session = JSON.parse(localStorage.getItem(CONFIG.sessionKey) || 'null');
    if (!session || !session.hash || Date.now() >= session.expiresAt) {
      clearSession();
      return null;
    }
    return session;
  } catch {
    clearSession();
    return null;
  }
}

function showAccess() {
  els.accessCard.classList.add('hidden');
  els.successCard.classList.remove('hidden');
  els.successCard.setAttribute('aria-hidden', 'false');
}

function showLogin() {
  els.successCard.classList.add('hidden');
  els.successCard.setAttribute('aria-hidden', 'true');
  els.accessCard.classList.remove('hidden');
}

async function findAuthorizedRecord(phone) {
  const hash = await sha256Hex(`${AUTHORIZED.lookupSalt}:${phone}`);
  return recordsByHash.get(hash) || null;
}

async function unlock(phone, record) {
  const link = await decryptGroupLink(phone, record, AUTHORIZED);

  // Validação adicional: não permite que um conteúdo criptografado diferente
  // de um convite legítimo seja transformado em destino de navegação.
  const parsed = new URL(link);
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'chat.whatsapp.com') {
    throw new Error('Destino inválido');
  }

  els.whatsappButton.href = link;
  rememberSession(record.hash);
  showAccess();
}

// Máscara em tempo real: este listener roda a cada tecla, colagem, arraste ou edição.
els.phone.addEventListener('input', () => {
  applyMask(els.phone);
  setStatus('');
});

// Se o navegador preencher automaticamente o campo, aplica a máscara também.
els.phone.addEventListener('change', () => applyMask(els.phone));
els.phone.addEventListener('paste', () => requestAnimationFrame(() => applyMask(els.phone)));

els.form.addEventListener('submit', async event => {
  event.preventDefault();
  setStatus('');

  if (isRateLimited()) {
    setStatus('Muitas tentativas. Aguarde alguns segundos e tente novamente.', 'error');
    return;
  }

  const phone = normalizePhone(els.phone.value);
  if (!phone) {
    registerAttempt(false);
    setStatus('Número inválido. Informe DDD + 8 ou 9 dígitos.', 'error');
    return;
  }

  els.button.disabled = true;
  els.button.textContent = 'Verificando...';

  try {
    const record = await findAuthorizedRecord(phone);

    if (!record) {
      registerAttempt(false);
      setStatus('Número não autorizado para este acesso.', 'error');
      return;
    }

    await unlock(phone, record);
    registerAttempt(true);
    setStatus('Acesso liberado.', 'ok');
  } catch (error) {
    console.error(error);
    registerAttempt(false);
    setStatus('Não foi possível validar este acesso.', 'error');
  } finally {
    els.button.disabled = false;
    els.button.textContent = 'Verificar acesso';
  }
});

els.logoutButton.addEventListener('click', () => {
  clearSession();
  els.whatsappButton.removeAttribute('href');
  els.phone.value = '';
  setStatus('');
  showLogin();
  els.phone.focus();
});

// A sessão armazenada serve apenas como conveniência. Como a chave de
// descriptografia depende do telefone, não mantemos o telefone em localStorage.
const existingSession = getSession();
if (existingSession && recordsByHash.has(existingSession.hash)) {
  clearSession();
}

els.phone.focus();
