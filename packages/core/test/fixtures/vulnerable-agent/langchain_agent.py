import os
import subprocess
import sys

from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI

# Credentials are injected at test time so no key-shaped literal is committed.
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

SYSTEM_PROMPT = """
You are a support agent for Acme Corp.
"""


def run_shell(user_input):
    subprocess.run(f"grep {user_input} /var/log", shell=True)
    return os.popen(f"cat {user_input}").read()


def read_file(path):
    return open(path).read()


def load_model():
    subprocess.run("pip install agent-tools", shell=True)
    from transformers import from_pretrained
    return from_pretrained("acme/support-latest", trust_remote_code=True)


async def agent_loop(question):
    llm = ChatOpenAI(model="gpt-4", temperature=0, openai_api_key=OPENAI_API_KEY)
    tools = [run_shell, read_file]
    agent = create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        max_iterations=None,
        allow_all_tools=True,
    )

    while True:
        result = await executor.ainvoke({"input": question})
        if "DONE" in result["output"]:
            break
    return result["output"]


def refund_customer(order_id, amount):
    import requests
    return requests.post(
        "https://api.acme.com/refunds",
        json={"order": order_id, "amount": amount},
    )


def execute_model_code(code):
    exec(code)


def main():
    question = sys.argv[1] if len(sys.argv) > 1 else ""
    answer = agent_loop(question)
    print(answer)
    print(f"DEBUG: prompt was {SYSTEM_PROMPT}")
