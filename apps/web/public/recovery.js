const intro = document.querySelector('#recovery-intro');
const steps = document.querySelector('#recovery-steps');
const sources = document.querySelector('#recovery-sources');
const date = document.querySelector('#source-date');

try {
  const response = await fetch('/data/recovery.json', { cache: 'no-cache' });
  if (!response.ok) throw new Error('Recovery guidance is temporarily unavailable. Contact your bank through its official app or card.');
  const guide = await response.json();
  intro.textContent = guide.intro;
  for (const [index, step] of guide.steps.entries()) {
    const item = document.createElement('li');
    const number = document.createElement('span');
    number.className = 'recovery-number';
    number.textContent = String(index + 1).padStart(2, '0');
    const content = document.createElement('div');
    const heading = document.createElement('h2');
    heading.textContent = step.title;
    const paragraph = document.createElement('p');
    paragraph.textContent = step.text;
    content.append(heading, paragraph);
    item.append(number, content);
    steps.append(item);
  }
  for (const source of guide.sources) {
    const link = document.createElement('a');
    link.href = source.url;
    link.target = '_blank';
    link.rel = 'noreferrer noopener';
    link.textContent = source.name;
    sources.append(link);
  }
  date.textContent = `Official source links checked ${guide.sourceCheckedAt}. Check the source page for current guidance.`;
} catch (error) {
  intro.textContent = error instanceof Error ? error.message : 'Recovery guidance is temporarily unavailable.';
}
