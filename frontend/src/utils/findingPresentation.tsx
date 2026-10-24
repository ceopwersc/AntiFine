export function findingTechnology(file: string) {
  if (file.endsWith('.tf')) return 'Terraform';
  if (file.endsWith('.yaml') || file.endsWith('.yml')) return 'Kubernetes';
  if (file.toLowerCase().includes('dockerfile')) return 'Dockerfile';
  return 'Infrastructure';
}

export function renderExplanation(explanation: string) {
  return explanation.split(/\n+/).map((line, index) => {
    const heading = line.replace(/[*#]/g, '').replace(/:$/, '').trim();
    const section = /^(What was detected|Why it matters|Compliance impact|Recommended action|Developer takeaway)$/i.test(heading);
    return section
      ? <h4 key={`${line}-${index}`}>{heading}</h4>
      : line.trim() ? <p key={`${line}-${index}`}>{line.replace(/^\s*[-*]\s*/, '')}</p> : null;
  });
}