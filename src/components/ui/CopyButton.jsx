import { useEffect, useState } from "react";
import { copyText } from "../../utils/clipboard";

/** Кнопка «Скопировать» с ответом: «Скопировано» или, если браузер не дал доступа к буферу, «Выделите и скопируйте вручную». */
export default function CopyButton({ text, label = "Скопировать", className }) {
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!result) return undefined;
    const timer = setTimeout(() => setResult(null), 2500);
    return () => clearTimeout(timer);
  }, [result]);

  const caption = result === "ok" ? "Скопировано" : result === "fail" ? "Не удалось — выделите и скопируйте вручную" : label;

  return (
    <button
      type="button"
      onClick={async () => setResult((await copyText(text)) ? "ok" : "fail")}
      className={className}
    >
      {caption}
    </button>
  );
}
