const doc = {
  sections: [...document.querySelectorAll(".docs-main section[id]")],
  links: [...document.querySelectorAll(".docs-nav a[data-section]")],
  nav: document.querySelector(".docs-nav"),
  copyButtons: [...document.querySelectorAll("[data-copy]")],
};

document.getElementById("year").textContent = String(new Date().getFullYear());

const normalize = (id) => decodeURIComponent(id).toLowerCase();

doc.links.forEach((link) => {
  link.addEventListener("click", () => {
    if (window.matchMedia("(max-width: 920px)").matches) doc.nav.classList.remove("open");
  });
});

const onClickCopy = async (button) => {
  const code = button.parentElement.querySelector("code");
  const text = code ? code.textContent : "";
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied";
    button.classList.add("copied");
    setTimeout(() => {
      button.textContent = original;
      button.classList.remove("copied");
    }, 1400);
  } catch {
    button.textContent = "Copy failed";
    setTimeout(() => (button.textContent = "Copy"), 1400);
  }
};

doc.copyButtons.forEach((button) => button.addEventListener("click", () => onClickCopy(button)));

const highlightSection = () => {
  const probe = 96;
  let current = doc.sections[0]?.id ?? "overview";
  for (const section of doc.sections) {
    if (section.getBoundingClientRect().top <= probe) current = section.id;
  }
  doc.links.forEach((link) => {
    link.classList.toggle("active", normalize(link.dataset.section ?? "") === normalize(current));
  });
};

highlightSection();
window.addEventListener("scroll", highlightSection, { passive: true });

navigator.serviceWorker?.register("/sw.js").catch(() => {});