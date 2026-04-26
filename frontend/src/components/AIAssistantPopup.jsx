import { useState, useRef, useEffect } from "react";
import { MessageSquare, X, Send, Bot, User } from "lucide-react";

export default function AIAssistantPopup() {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef(null);
  const [messages, setMessages] = useState([
    { role: 'bot', content: "Hello! I'm your autonomous security agent. How can I help you secure your edge layer today?" }
  ]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping, open]);

  const handleSend = () => {
    if (!input.trim()) return;
    
    setMessages(prev => [...prev, { role: 'user', content: input }]);
    setInput("");
    setIsTyping(true);

    setTimeout(() => {
      const mockResponses = [
        "I've cross-referenced the global threat intelligence database. Your edge framework remains secure.",
        "There were 12 blocked intrusion attempts originating from abnormal ASN ranges in the last hour.",
        "Should I isolate those IP addresses and deploy a WAF firewall block rule immediately?",
        "Security protocols operating normally. I recommend initiating a deep credentials scan when possible.",
        "Your firewall configurations look optimal but I would suggest enabling rate limiting on the `/auth` endpoints."
      ];
      const randomResponse = mockResponses[Math.floor(Math.random() * mockResponses.length)];
      setMessages(prev => [...prev, { role: 'bot', content: randomResponse }]);
      setIsTyping(false);
    }, 1200);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleSend();
    }
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 font-sans">
      {/* Popup Window */}
      {open && (
        <div className="absolute bottom-16 right-0 w-80 h-96 glass-panel border border-accent/30 shadow-[0_0_20px_rgba(0,212,170,0.15)] flex flex-col mb-4 overflow-hidden animate-fade-in-up">
          <div className="bg-bg2/90 border-b border-white/10 p-4 flex justify-between items-center relative overflow-hidden">
            <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-accent/10 to-transparent pointer-events-none" />
            <div className="flex items-center gap-2">
              <Bot className="text-accent" size={20} />
              <span className="font-bold text-sm text-white">Ask WebGuard AI</span>
            </div>
            <button onClick={() => setOpen(false)} className="text-gray-400 hover:text-white transition-colors">
              <X size={18} />
            </button>
          </div>
          
          <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 text-sm" ref={scrollRef}>
            {messages.map((msg, idx) => (
              <div key={idx} className={`flex gap-2 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-8 h-8 rounded-full flex-shrink-0 flex items-center justify-center border ${msg.role === 'user' ? 'bg-bg2 border-gray-600' : 'bg-accent/20 border-accent/40'}`}>
                  {msg.role === 'user' ? <User size={16} className="text-gray-400" /> : <Bot size={16} className="text-accent" />}
                </div>
                <div className={`border rounded-lg p-3 ${msg.role === 'user' ? 'bg-bg/80 border-gray-700 text-white rounded-tr-none' : 'bg-white/5 border-white/10 text-gray-300 rounded-tl-none'}`}>
                  {msg.content}
                </div>
              </div>
            ))}
            
            {isTyping && (
              <div className="flex gap-2">
                <div className="w-8 h-8 rounded-full bg-accent/20 flex-shrink-0 flex items-center justify-center border border-accent/40">
                  <Bot size={16} className="text-accent" />
                </div>
                <div className="bg-white/5 border border-white/10 rounded-lg rounded-tl-none p-3 text-gray-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce"></span>
                  <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }}></span>
                  <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }}></span>
                </div>
              </div>
            )}
          </div>
          
          <div className="p-3 border-t border-white/10 bg-bg2/50 flex gap-2">
            <input 
              type="text" 
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a command..." 
              className="flex-1 bg-bg3 border border-white/10 rounded-md px-3 py-2 text-sm text-white outline-none focus:border-accent/50 transition-colors" 
            />
            <button 
              onClick={handleSend}
              disabled={!input.trim() || isTyping}
              className="bg-accent/10 text-accent p-2 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Send size={18} />
            </button>
          </div>
        </div>
      )}

      {/* Toggle Button */}
      <button 
        onClick={() => setOpen(!open)}
        className="w-14 h-14 bg-bg2 border border-accent/40 rounded-full flex items-center justify-center text-accent hover:bg-accent hover:text-bg2 shadow-[0_0_15px_rgba(0,212,170,0.3)] transition-all glow group relative"
      >
        <span className="absolute -inset-1 bg-accent/20 rounded-full animate-ping pointer-events-none group-hover:hidden"></span>
        {open ? <X size={24} /> : <MessageSquare size={24} />}
      </button>
    </div>
  );
}
