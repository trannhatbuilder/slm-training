import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

# ═══════════════════════════════════════════════════════
# CẤU HÌNH
# ═══════════════════════════════════════════════════════
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"
ADAPTER_PATH = str(PROJECT_ROOT / "checkpoints" / "slm-adapter-v0.1")  # Đường dẫn đến thư mục adapter

# ═══════════════════════════════════════════════════════
# LOAD MODEL
# ═══════════════════════════════════════════════════════
print("Loading model...")
tokenizer = AutoTokenizer.from_pretrained(ADAPTER_PATH)

# Chọn device: GPU nếu có, nếu không thì CPU
device = "cuda" if torch.cuda.is_available() else "cpu"
dtype = torch.float16 if device == "cuda" else torch.float32

print(f"Using device: {device}")
print(f"Using dtype: {dtype}")

base_model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype=dtype,
    device_map="auto" if device == "cuda" else None,
)

if device == "cpu":
    base_model = base_model.to(device)

model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
model.eval()

print(f"✅ Model loaded! VRAM: {torch.cuda.memory_allocated() / 1e9:.2f} GB" if device == "cuda" else "✅ Model loaded!")

# ═══════════════════════════════════════════════════════
# HÀM CHAT
# ═══════════════════════════════════════════════════════
def chat(question: str, max_tokens: int = 512) -> str:
    """chat with model and return to response"""
    messages = [{"role": "user", "content": question}]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            do_sample=False,
            temperature=1.0,
        )
    
    response = tokenizer.decode(
        output_ids[0][inputs['input_ids'].shape[1]:],
        skip_special_tokens=True
    )
    return response

# ═══════════════════════════════════════════════════════
# INTERACTIVE CHAT LOOP
# ═══════════════════════════════════════════════════════
print("\n" + "="*70)
print("🤖 A01:2025 Broken Access Control Expert (v0.6)")
print("="*70)
print("Enter your question. Enter 'quit' or 'exit' to exit.")
print("="*70 + "\n")

while True:
    try:
        question = input("❓ You: ").strip()
        
        if question.lower() in ['quit', 'exit', 'q']:
            print("👋 Bye!")
            break
        
        if not question:
            continue
        
        print("\n💬 AI: ", end="", flush=True)
        response = chat(question)
        print(response)
        print()
        
    except KeyboardInterrupt:
        print("\n👋 Bye!")
        break
    except Exception as e:
        print(f"\n❌ Error: {e}\n")