const form = document.querySelector("#analysis-form");
const formView = document.querySelector("#form-view");
const loadingView = document.querySelector("#loading-view");
const resultView = document.querySelector("#result-view");
const errorBox = document.querySelector("#error-box");
const errorMessage = document.querySelector("#error-message");
const messageInput = document.querySelector("#message");
const imageInput = document.querySelector("#image");
const uploadTitle = document.querySelector("#upload-title");
const uploadDetail = document.querySelector("#upload-detail");
const submitButton = document.querySelector("#submit-button");
const loadingTitle = document.querySelector("#loading-title");
const loadingDetail = document.querySelector("#loading-detail");
const loadingProgress = document.querySelector("#loading-progress");
const feedbackRow = document.querySelector("#feedback-row");
const feedbackReasons = document.querySelector("#feedback-reasons");
const feedbackStatus = document.querySelector("#feedback-status");

let currentAnalysis = null;
let loadingTimers = [];

const loadingSteps = [
  ["Leyendo el mensaje…", "Identificamos quién escribe y qué te pide.", "28%"],
  ["Contrastando señales…", "Comprobamos dominios, enlaces y patrones conocidos.", "66%"],
  ["Preparando una respuesta clara…", "Ordenamos la evidencia y la acción más prudente.", "88%"],
];

function setView(view) {
  formView.hidden = view !== "form";
  loadingView.hidden = view !== "loading";
  resultView.hidden = view !== "result";
}

function showError(message) {
  setView("form");
  errorMessage.textContent = message;
  errorBox.hidden = false;
  errorBox.focus();
}

function clearError() {
  errorBox.hidden = true;
  errorMessage.textContent = "";
}

function startLoading() {
  setView("loading");
  submitButton.disabled = true;
  loadingSteps.forEach((step, index) => {
    const timer = window.setTimeout(() => {
      loadingTitle.textContent = step[0];
      loadingDetail.textContent = step[1];
      loadingProgress.style.width = step[2];
    }, index * 950);
    loadingTimers.push(timer);
  });
}

function stopLoading() {
  loadingTimers.forEach((timer) => window.clearTimeout(timer));
  loadingTimers = [];
  submitButton.disabled = false;
  loadingProgress.style.width = "18%";
}

function createSignalItem(signal) {
  const item = document.createElement("div");
  item.className = `signal-item ${signal.severity}`;

  const dot = document.createElement("i");
  dot.setAttribute("aria-hidden", "true");
  item.appendChild(dot);

  const copy = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = signal.summary;
  copy.appendChild(title);
  if (signal.detail) {
    const detail = document.createElement("span");
    detail.textContent = signal.detail;
    copy.appendChild(detail);
  }
  item.appendChild(copy);
  return item;
}

function renderResult(data) {
  currentAnalysis = data;
  const isScam = data.level === "estafa";
  resultView.classList.toggle("is-scam", isScam);
  document.querySelector("#verdict-text").textContent = isScam
    ? "Estafa"
    : "No puedo confirmarlo";
  const typeBox = document.querySelector("#message-type");
  const typeText = document.querySelector("#message-type-text");
  const typeConfidence = document.querySelector("#message-type-confidence");
  const typeLabels = {
    phishing: "phishing o suplantación",
    spam: "spam o publicidad",
    transaccional: "mensaje transaccional",
    personal: "conversación personal",
    desconocido: "tipo no concluyente",
  };
  typeText.textContent = typeLabels[data.message_type] || typeLabels.desconocido;
  const confidence = Math.round((data.message_type_confidence || 0) * 100);
  typeConfidence.textContent = confidence ? `${confidence}% orientativo` : "";
  typeBox.hidden = false;
  document.querySelector("#result-headline").textContent = data.headline;
  document.querySelector("#result-summary").textContent = data.summary;
  document.querySelector("#result-action").textContent = data.action;

  const reasonList = document.querySelector("#reason-list");
  reasonList.replaceChildren();
  data.reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonList.appendChild(item);
  });

  const incidentList = document.querySelector("#incident-list");
  incidentList.replaceChildren();
  data.incident_steps.forEach((step) => {
    const item = document.createElement("li");
    item.textContent = step;
    incidentList.appendChild(item);
  });

  const signalList = document.querySelector("#signal-list");
  signalList.replaceChildren();
  const visibleSignals = data.signals.filter((signal) => signal.status === "hit");
  if (visibleSignals.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "No había señales técnicas que se pudieran verificar.";
    signalList.appendChild(empty);
  } else {
    visibleSignals.forEach((signal) => signalList.appendChild(createSignalItem(signal)));
  }

  feedbackRow.hidden = false;
  feedbackReasons.hidden = true;
  feedbackStatus.textContent = "";
  setView("result");
  resultView.focus();
}

async function getErrorMessage(response) {
  try {
    const payload = await response.json();
    if (Array.isArray(payload.detail)) {
      return payload.detail.map((item) => item.msg).join(" ");
    }
    return payload.detail || "Revisa el mensaje y vuelve a intentarlo.";
  } catch {
    return "El servicio no responde. Vuelve a intentarlo dentro de un momento.";
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  if (!messageInput.value.trim() && imageInput.files.length === 0) {
    showError("Pega el texto del mensaje o añade una captura.");
    messageInput.focus();
    return;
  }

  const data = new FormData(form);
  startLoading();
  try {
    const response = await fetch("/api/v1/analyze", { method: "POST", body: data });
    if (!response.ok) {
      throw new Error(await getErrorMessage(response));
    }
    renderResult(await response.json());
  } catch (error) {
    showError(error.message || "No se ha podido completar el análisis.");
  } finally {
    stopLoading();
  }
});

document.querySelector("#example-button").addEventListener("click", () => {
  messageInput.value =
    "CaixaBank: Su cuenta ha sido bloqueada. Verifique sus datos en las próximas 24 horas en https://caixabank-seguridad.top/acceso";
  messageInput.focus();
});

document.querySelector("#spam-example-button").addEventListener("click", () => {
  messageInput.value =
    "Oferta exclusiva: 70% de descuento. Suscríbete hoy y consigue tu cupón. Para dejar de recibir publicidad responde BAJA.";
  messageInput.focus();
});

imageInput.addEventListener("change", () => {
  const file = imageInput.files[0];
  if (!file) {
    uploadTitle.textContent = "Añadir una captura";
    uploadDetail.textContent = "JPG, PNG o WEBP · máximo 5 MB";
    return;
  }
  uploadTitle.textContent = file.name;
  uploadDetail.textContent = `${Math.max(1, Math.round(file.size / 1024))} KB · lista para analizar`;
});

document.querySelector("#reset-button").addEventListener("click", () => {
  currentAnalysis = null;
  form.reset();
  clearError();
  uploadTitle.textContent = "Añadir una captura";
  uploadDetail.textContent = "JPG, PNG o WEBP · máximo 5 MB";
  setView("form");
  messageInput.focus();
});

document.querySelector("#copy-button").addEventListener("click", async (event) => {
  if (!currentAnalysis) return;
  const level = currentAnalysis.level === "estafa" ? "ESTAFA" : "NO PUEDO CONFIRMARLO";
  const type = document.querySelector("#message-type-text").textContent;
  const copy = `${level}\nTipo: ${type}\n${currentAnalysis.headline}\n${currentAnalysis.action}`;
  try {
    await navigator.clipboard.writeText(copy);
    event.currentTarget.lastChild.textContent = " Copiado";
    window.setTimeout(() => {
      event.currentTarget.lastChild.textContent = " Copiar veredicto";
    }, 1600);
  } catch {
    showError("No se pudo copiar. Selecciona el texto del veredicto manualmente.");
  }
});

function shareText() {
  const level = currentAnalysis.level === "estafa" ? "ESTAFA" : "NO PUEDO CONFIRMARLO";
  const recovery = currentAnalysis.incident_steps.map((step) => `• ${step}`).join("\n");
  const type = document.querySelector("#message-type-text").textContent;
  return `${level}\nTipo orientativo: ${type}\n${currentAnalysis.headline}\n\n${currentAnalysis.action}\n\nSi ya actuaste:\n${recovery}`;
}

document.querySelector("#share-button").addEventListener("click", async (event) => {
  if (!currentAnalysis) return;
  const payload = { title: "Resultado de Alerta Clara", text: shareText() };
  try {
    if (navigator.share) {
      await navigator.share(payload);
    } else {
      await navigator.clipboard.writeText(payload.text);
      event.currentTarget.textContent = "Copiado para compartir";
      window.setTimeout(() => {
        event.currentTarget.textContent = "Compartir con alguien de confianza";
      }, 1800);
    }
  } catch (error) {
    if (error.name !== "AbortError") {
      feedbackStatus.textContent = "No se pudo compartir; prueba a copiar el veredicto.";
    }
  }
});

async function sendFeedback(userSaid, reasonCode = null) {
  const response = await fetch(`/api/v1/analyses/${currentAnalysis.id}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_said: userSaid, reason_code: reasonCode }),
  });
  if (!response.ok) throw new Error("feedback_failed");
  feedbackReasons.hidden = true;
  feedbackStatus.textContent = "Gracias. Tu respuesta queda registrada para revisión.";
}

feedbackRow.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-feedback]");
  if (!button || !currentAnalysis) return;
  if (button.dataset.feedback === "incorrecto") {
    feedbackReasons.hidden = false;
    feedbackReasons.querySelector("button").focus();
    return;
  }
  try {
    await sendFeedback(button.dataset.feedback);
  } catch {
    feedbackStatus.textContent = "No se pudo guardar la respuesta.";
  }
});

feedbackReasons.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-reason]");
  if (!button || !currentAnalysis) return;
  try {
    await sendFeedback("incorrecto", button.dataset.reason);
  } catch {
    feedbackStatus.textContent = "No se pudo guardar la respuesta.";
  }
});
