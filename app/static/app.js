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

const pasteButton = document.querySelector("#paste-button");
const pageShell = document.querySelector(".page-shell");

function setView(view) {
  formView.hidden = view !== "form";
  loadingView.hidden = view !== "loading";
  resultView.hidden = view !== "result";
  if (pageShell) {
    pageShell.classList.toggle("has-result", view === "result");
  }
}

if (pasteButton) {
  pasteButton.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        messageInput.focus();
        return;
      }
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        messageInput.value = text.trim();
        clearError();
        const span = pasteButton.querySelector("span");
        if (span) {
          const original = span.textContent;
          span.textContent = "¡Pegado!";
          window.setTimeout(() => {
            span.textContent = original;
          }, 1500);
        }
      } else {
        messageInput.focus();
      }
    } catch {
      messageInput.focus();
    }
  });
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
  if (resultView) {
    resultView.classList.toggle("is-scam", isScam);
  }

  const verdictEl = document.querySelector("#verdict-text");
  if (verdictEl) {
    verdictEl.textContent = isScam ? "Estafa" : "No puedo confirmarlo";
  }

  const headlineEl = document.querySelector("#result-headline");
  if (headlineEl) {
    headlineEl.textContent = data.headline || "";
  }

  const summaryEl = document.querySelector("#result-summary");
  if (summaryEl) {
    summaryEl.textContent = data.summary || "";
  }

  const actionEl = document.querySelector("#result-action");
  if (actionEl) {
    actionEl.textContent = data.action || "";
  }

  // Botón de llamada al canal oficial comprobado
  const officialBox = document.querySelector("#official-verification-box");
  const officialLink = document.querySelector("#official-call-link");
  const officialText = document.querySelector("#official-call-text");
  const officialNote = document.querySelector("#official-verification-note");
  if (
    data.official_verification &&
    data.official_verification.official_numbers &&
    data.official_verification.official_numbers.length > 0
  ) {
    const primary = data.official_verification.official_numbers[0];
    const rawNumber = typeof primary === "object" ? primary.number : primary;
    const verifiedAt = typeof primary === "object" && primary.verified_at ? primary.verified_at : "2026-08-18";
    const formattedPhone = rawNumber.replace(/(\d{3})(?=\d)/g, "$1 ").trim();
    if (officialLink) {
      officialLink.href = `tel:${rawNumber}`;
    }
    if (officialText) {
      officialText.textContent = `Llamar a ${data.official_verification.entity_name} · ${formattedPhone}`;
    }
    if (officialNote) {
      officialNote.textContent = `Publicado por ${data.official_verification.entity_name} · comprobado el ${verifiedAt}. Ante cualquier duda, llama al número que figura al dorso de tu tarjeta física.`;
    }
    if (officialBox) {
      officialBox.hidden = false;
    }
  } else if (officialBox) {
    officialBox.hidden = true;
  }

  // Clasificación orientativa sin porcentajes
  const typeBox = document.querySelector("#message-type");
  const typeText = document.querySelector("#message-type-text");
  const typeQualitative = document.querySelector("#message-type-qualitative");
  const typeConfidence = document.querySelector("#message-type-confidence");
  const typeLabels = {
    phishing: "Suplantación de identidad (Phishing)",
    spam: "Spam o publicidad no solicitada",
    transaccional: "Notificación transaccional legítima",
    personal: "Mensaje personal",
    desconocido: "No concluyente",
  };
  if (typeText) {
    typeText.textContent = typeLabels[data.message_type] || typeLabels.desconocido;
  }
  if (typeQualitative) {
    if (data.message_type === "phishing") {
      typeQualitative.textContent = " · Alta probabilidad por patrones de ingeniería social";
    } else if (data.message_type === "spam") {
      typeQualitative.textContent = " · Contenido publicitario comercial";
    } else {
      typeQualitative.textContent = "";
    }
  } else if (typeConfidence) {
    typeConfidence.textContent = "";
  }
  if (typeBox) {
    typeBox.hidden = false;
  }

  const reasonList = document.querySelector("#reason-list");
  if (reasonList) {
    reasonList.replaceChildren();
    (data.reasons || []).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonList.appendChild(item);
    });
  }

  const incidentList = document.querySelector("#incident-list");
  if (incidentList) {
    incidentList.replaceChildren();
    (data.incident_steps || []).forEach((step) => {
      const item = document.createElement("li");
      item.textContent = step;
      incidentList.appendChild(item);
    });
  }

  const signalList = document.querySelector("#signal-list");
  if (signalList) {
    signalList.replaceChildren();
    const visibleSignals = (data.signals || []).filter((signal) => signal.status === "hit");
    if (visibleSignals.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No había señales técnicas que se pudieran verificar.";
      signalList.appendChild(empty);
    } else {
      visibleSignals.forEach((signal) => signalList.appendChild(createSignalItem(signal)));
    }
  }

  // Asegurar que las comprobaciones técnicas estén colapsadas por defecto
  const evidenceDetails = document.querySelector(".evidence-details");
  if (evidenceDetails) {
    evidenceDetails.open = false;
  }

  if (feedbackRow) {
    feedbackRow.hidden = false;
  }
  if (feedbackReasons) {
    feedbackReasons.hidden = true;
  }
  if (feedbackStatus) {
    feedbackStatus.textContent = "";
  }
  setView("result");
  if (resultView) {
    resultView.focus();
  }
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

const exampleBtn = document.querySelector("#example-button");
if (exampleBtn) {
  exampleBtn.addEventListener("click", () => {
    if (messageInput) {
      messageInput.value =
        "CaixaBank: Su cuenta ha sido bloqueada. Verifique sus datos en las próximas 24 horas en https://caixabank-seguridad.top/acceso";
      messageInput.focus();
    }
  });
}

const spamExampleBtn = document.querySelector("#spam-example-button");
if (spamExampleBtn) {
  spamExampleBtn.addEventListener("click", () => {
    if (messageInput) {
      messageInput.value =
        "Oferta exclusiva: 70% de descuento. Suscríbete hoy y consigue tu cupón. Para dejar de recibir publicidad responde BAJA.";
      messageInput.focus();
    }
  });
}

if (imageInput) {
  imageInput.addEventListener("change", () => {
    const file = imageInput.files[0];
    if (!file) {
      if (uploadTitle) uploadTitle.textContent = "Añadir una captura";
      if (uploadDetail) uploadDetail.textContent = "JPG, PNG o WEBP · máximo 5 MB";
      return;
    }
    if (uploadTitle) uploadTitle.textContent = file.name;
    if (uploadDetail) {
      uploadDetail.textContent = `${Math.max(1, Math.round(file.size / 1024))} KB · lista para analizar`;
    }
  });
}

const resetBtn = document.querySelector("#reset-button");
if (resetBtn) {
  resetBtn.addEventListener("click", () => {
    currentAnalysis = null;
    if (form) form.reset();
    clearError();
    if (uploadTitle) uploadTitle.textContent = "Añadir una captura";
    if (uploadDetail) uploadDetail.textContent = "JPG, PNG o WEBP · máximo 5 MB";
    setView("form");
    if (messageInput) messageInput.focus();
  });
}

const copyBtn = document.querySelector("#copy-button");
if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    if (!currentAnalysis) return;
    const level = currentAnalysis.level === "estafa" ? "ESTAFA" : "NO PUEDO CONFIRMARLO";
    const typeEl = document.querySelector("#message-type-text");
    const type = typeEl ? typeEl.textContent : "";
    const copy = `${level}\nTipo: ${type}\n${currentAnalysis.headline}\n${currentAnalysis.action}`;
    try {
      await navigator.clipboard.writeText(copy);
      const originalText = copyBtn.textContent;
      copyBtn.textContent = " Copiado";
      window.setTimeout(() => {
        copyBtn.textContent = originalText;
      }, 1600);
    } catch {
      showError("No se pudo copiar. Selecciona el texto del veredicto manualmente.");
    }
  });
}

function shareText() {
  if (!currentAnalysis) return "";
  const level = currentAnalysis.level === "estafa" ? "ESTAFA" : "NO PUEDO CONFIRMARLO";
  const recovery = (currentAnalysis.incident_steps || []).map((step) => `• ${step}`).join("\n");
  const typeEl = document.querySelector("#message-type-text");
  const type = typeEl ? typeEl.textContent : "";
  return `${level}\nTipo orientativo: ${type}\n${currentAnalysis.headline}\n\n${currentAnalysis.action}\n\nSi ya actuaste:\n${recovery}`;
}

const shareBtn = document.querySelector("#share-button");
if (shareBtn) {
  shareBtn.addEventListener("click", async (event) => {
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
      if (error && error.name !== "AbortError") {
        if (feedbackStatus) {
          feedbackStatus.textContent = "No se pudo compartir; prueba a copiar el veredicto.";
        }
      }
    }
  });
}

async function sendFeedback(userSaid, reasonCode = null) {
  if (!currentAnalysis) return;
  const response = await fetch(`/api/v1/analyses/${currentAnalysis.id}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_said: userSaid, reason_code: reasonCode }),
  });
  if (!response.ok) throw new Error("feedback_failed");
  if (feedbackReasons) feedbackReasons.hidden = true;
  if (feedbackStatus) {
    feedbackStatus.textContent = "Gracias. Tu respuesta queda registrada para revisión.";
  }
}

if (feedbackRow) {
  feedbackRow.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-feedback]");
    if (!button || !currentAnalysis) return;
    if (button.dataset.feedback === "incorrecto") {
      if (feedbackReasons) {
        feedbackReasons.hidden = false;
        const firstBtn = feedbackReasons.querySelector("button");
        if (firstBtn) firstBtn.focus();
      }
      return;
    }
    try {
      await sendFeedback(button.dataset.feedback);
    } catch {
      if (feedbackStatus) feedbackStatus.textContent = "No se pudo guardar la respuesta.";
    }
  });
}

if (feedbackReasons) {
  feedbackReasons.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-reason]");
    if (!button || !currentAnalysis) return;
    try {
      await sendFeedback("incorrecto", button.dataset.reason);
    } catch {
      if (feedbackStatus) feedbackStatus.textContent = "No se pudo guardar la respuesta.";
    }
  });
}
