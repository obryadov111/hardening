/**
 * Копирование в буфер обмена. navigator.clipboard есть только в защищённом контексте (HTTPS, localhost):
 * по http://<IP> в локальной сети его нет, и вызов через ?. молча ничего не делал. Тогда — старый способ
 * через скрытое поле и execCommand("copy"). Возвращает true, если текст скопирован.
 */
export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // нет разрешения — пробуем старый способ
    }
  }
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.appendChild(field);
  field.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    document.body.removeChild(field);
  }
}
