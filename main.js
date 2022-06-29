import { generateMac } from "./desEncrypter.js";
import "./style.css";

const generateButton = document.querySelector("#generate");

generateButton.addEventListener("click", () => {
  const inputText = document.querySelector("#message").value.toString();
  const inputMac = document.querySelector("#mac").value.toString();

  const mac = generateMac(inputText, inputMac);
  document.querySelector("#generateMac").innerHTML = `
  <p> Mac Generada: ${mac}</p>
`;
});
