import {
BookOpen,
Bot,
Copy,
MessageSquareText,
RefreshCw,
Send,
Trash2,
WifiOff,
X
} from 'lucide-react';
import { useEffect,useRef,useState,type ReactNode } from 'react';
import { askAntiFine,fetchAIHealth,type AskContext,type AskMessage,type AskResponse } from '../api';
import { normalizeSeverity } from '../types';
import { SeverityBadge } from './WorkstationUI';
type AssistantMessage = AskMessage & { sources?: AskResponse['sources'] };
function renderMarkdown(markdown: string) {
  const renderInline = (value: string) => value.split(/(`[^`]+`)/g).map((part, partIndex) => part.startsWith('`') && part.endsWith('`')
    ? <code key={partIndex}>{part.slice(1, -1)}</code>
    : part);
  const lines = markdown.split(/\r?\n/);
  const nodes: ReactNode[] = [];
  let inCode = false;
  let codeLines: string[] = [];
  let listItems: ReactNode[] = [];
  const flushList = () => {
    if (listItems.length) {
      nodes.push(<ul key={`list-${nodes.length}`}>{listItems}</ul>);
      listItems = [];
    }
  };
  lines.forEach((line, index) => {
    if (line.trim().startsWith('```')) {
      if (inCode) {
        nodes.push(<pre className="assistant-code" key={`code-${index}`}><code>{codeLines.join('\n')}</code></pre>);
        codeLines = [];
      }
      inCode = !inCode;
      return;
    }
    if (inCode) {
      codeLines.push(line);
      return;
    }
    const content = line.replace(/^\s*[-*]\s/, '');
    if (!line.trim()) return;
    if (/^#{1,3}\s/.test(line)) {
      flushList();
      nodes.push(<h4 key={index}>{line.replace(/^#{1,3}\s/, '')}</h4>);
    } else if (/^\s*[-*]\s/.test(line)) {
      listItems.push(<li key={index}>{renderInline(content)}</li>);
    } else {
      flushList();
      nodes.push(<p key={index}>{renderInline(content)}</p>);
    }
  });
  flushList();
  return nodes;
}

export function AskAntiFinePage({
  context,
  initialQuestion,
  onClearContext,
  onNewChat,
}: {
  context?: AskContext;
  initialQuestion?: string;
  onClearContext: () => void;
  onNewChat: () => void;
}) {
  const [health, setHealth] = useState<Awaited<ReturnType<typeof fetchAIHealth>> | null>(null);
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [question, setQuestion] = useState(initialQuestion ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const suggestions = [
    'How does AntiFine detect high-entropy secrets?',
    'Why is TF-AWS-004 critical?',
    'Which CIS controls are currently failing?',
    'How does deterministic remediation work?',
    'What does PSS Restricted require?',
  ];

  const checkHealth = async () => {
    try {
      setHealth(await fetchAIHealth());
    } catch {
      setHealth({ enabled: true, available: false, provider: 'ollama', model: 'qwen2.5:7b', error: 'Backend unavailable' });
    }
  };
  useEffect(() => { void fetchAIHealth().then(setHealth).catch(() => setHealth({enabled:false,available:false,provider:'ollama',model:'Unavailable'})); }, []);
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        composerRef.current?.focus();
      }
      if (event.key === 'Escape' && context) onClearContext();
    };
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, [context, onClearContext]);

  const sendQuestion = async (value = question) => {
    const trimmed = value.trim();
    if (!trimmed || loading) return;
    setQuestion('');
    setError('');
    const previousMessages = messages.map(({ role, content }) => ({ role, content })).slice(-10);
    setMessages((current) => [...current, { role: 'user', content: trimmed }]);
    setLoading(true);
    try {
      const response = await askAntiFine(trimmed, context, previousMessages);
      if (!response.answer?.trim()) throw new Error('The assistant returned an empty response.');
      setMessages((current) => [...current, { role: 'assistant', content: response.answer, sources: response.sources }]);
    } catch (requestError: any) {
      setError(requestError?.response?.data?.detail || 'Local AI is unavailable.');
    } finally {
      setLoading(false);
    }
  };
  const retry = () => {
    const lastQuestion = [...messages].reverse().find((message) => message.role === 'user')?.content;
    if (lastQuestion) void sendQuestion(lastQuestion);
  };
  const newChat = () => { setMessages([]); setError(''); setQuestion(''); onNewChat(); };
  const copyAnswer = async (content: string) => {
    if (!navigator.clipboard) {
      setError('Copy is unavailable in this browser context.');
      return;
    }
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setError('AntiFine could not copy this response.');
    }
  };
  const available = health?.available === true;

  return <div className="content-stack assistant-page">
    <div className="assistant-header">
      <div><div className="eyebrow">Local intelligence</div><h1>Ask AntiFine</h1><p>Local security intelligence for your infrastructure.</p></div>
      <div className="assistant-actions"><button className="button button-secondary" onClick={newChat}><MessageSquareText size={14} />New chat</button><button className="button button-secondary" onClick={() => { setMessages([]); setError(''); }} disabled={!messages.length}><Trash2 size={14} />Clear conversation</button></div>
    </div>
    <div className={`assistant-status ${available ? 'assistant-online' : 'assistant-offline'}`}>
      {available ? <Bot size={17} /> : <WifiOff size={17} />}
      <div><strong>{available ? 'Local AI ready' : health?.enabled === false ? 'Local AI disabled' : health ? 'Ollama unavailable' : 'Checking local AI…'}</strong><span>Answers are generated locally using Ollama and AntiFine’s local knowledge.</span></div>
      <span className="assistant-model">{health?.provider ?? 'ollama'} · {health?.model ?? 'qwen2.5:7b'}</span>
      {!available && health?.enabled !== false && <button className="text-button" onClick={() => void checkHealth()}>Retry connection</button>}
    </div>
    {context && <div className="assistant-context"><div><span>Analyzing</span><strong>{context.rule_id || context.finding_id}</strong></div><SeverityBadge severity={normalizeSeverity(context.severity)} /><code>{context.technology} · {context.finding_id}</code><button className="icon-button small" aria-label="Remove finding context" onClick={onClearContext}><X size={14} /></button></div>}
    <section className="panel assistant-panel">
      <div className="assistant-conversation" aria-live="polite">
        {!messages.length && <div className="assistant-empty"><div className="assistant-empty-icon"><MessageSquareText size={20} /></div><h2>What can I help you investigate?</h2><p>Ask about AntiFine rules, compliance mappings, remediation behavior, or a finding.</p><div className="suggestion-grid">{suggestions.map((suggestion) => <button key={suggestion} onClick={() => void sendQuestion(suggestion)}>{suggestion}<Send size={13} /></button>)}</div></div>}
        {messages.map((message, index) => <div className={`assistant-message ${message.role}`} key={`${message.role}-${index}`}><div className="message-meta">{message.role === 'user' ? 'You' : 'AntiFine · local assistant'}</div><div className="message-body">{message.role === 'assistant' ? renderMarkdown(message.content) : <p>{message.content}</p>}</div>{message.role === 'assistant' && <>{message.sources?.length ? <div className="source-list"><span className="source-label">Sources</span>{message.sources.map((source) => <div className="source-item" key={`${source.source}-${source.title}`}><BookOpen size={13} /><div><strong>{source.title}</strong><span>{source.source}{source.rule_id ? ` · ${source.rule_id}` : ''}</span></div></div>)}</div> : null}<div className="message-actions"><button className="text-button" onClick={() => void copyAnswer(message.content)}><Copy size={13} />{copied ? 'Copied' : 'Copy answer'}</button><button className="text-button" onClick={retry}><RefreshCw size={13} />Regenerate</button></div></>}</div>)}
        {loading && <div className="assistant-message assistant"><div className="message-meta">AntiFine · local assistant</div><div className="assistant-loading"><RefreshCw size={14} className="spin" />Analyzing locally…</div></div>}
        {error && <div className="assistant-error"><strong>Local AI is unavailable.</strong><span>AntiFine’s deterministic security engine remains fully operational.</span><button className="text-button" onClick={retry}>Retry</button></div>}
      </div>
      <div className="assistant-composer"><textarea ref={composerRef} value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void sendQuestion(); } }} placeholder="Ask about AntiFine, a finding, compliance rule, or remediation…" aria-label="Ask AntiFine a question" /><div className="composer-footer"><span><kbd>Enter</kbd> send · <kbd>Shift + Enter</kbd> newline · <kbd>⌘ K</kbd> focus</span><button className="button button-primary" onClick={() => void sendQuestion()} disabled={loading || !question.trim()}>{loading ? <><RefreshCw size={14} className="spin" />Analyzing…</> : <><Send size={14} />Send</>}</button></div></div>
    </section>
  </div>;
}