from schema import ExecutionMode
from schema import TargetProfile
from schema import ProfilerState
from langchain_core.messages import ToolMessage
from langsmith._openapi_client.types import run_select_field
from langgraph.prebuilt import ToolCallTransformer
from langchain_core.messages import SystemMessage, BaseMessage
from langgraph.prebuilt import ToolNode
from langgraph.graph import StateGraph, START, END
from langchain.messages import HumanMessage
from tools import tools
from langchain_openai import ChatOpenAI



graph=StateGraph(ProfilerState)

model_tools=model.bind_tools(tools)

#export From .env
api='fake api'

model = ChatOpenAI(
    api_key=api, base_url="https://apihub.agnes-ai.com/v1",model='agnes-2.0-flash'
)




def _select_execution_mode(p: TargetProfile) -> ExecutionMode:
    ds= p.data_sensitivity


    #confidentiality case
    health= ds.handles_health_records or 'HIPAA' in p.regulatory_flags
    other_regulated = (
        ds.handles_pii or ds.handles_financial_data
        or "PDPA" in p.regulatory_flags or "PCI_DSS" in p.regulatory_flags
    )

    #containment case
    hostile_risk= (
        p.target_type == "codebase"        # about to walk/parse untrusted files
        or ds.handles_credentials          # compromise here is high-value
        or p.confidence < 0.6              # unknown target = unknown risk
    )

    #feabsibile : air_gap cannot reach internet facing target
    reachable_offline = p.connectivity in ("offline", "internal", "containerised")

    if health and reachable_offline:
        return 'air_gap'
    if health or other_regulated:
        return 'privacy'
    if hostile_risk:
        return 'sandbox'
    return 'standard'
    








def llm_call(state: ProfilerState):
    messages = list(state.get("messages") or [])
    new: list[BaseMessage] = []

    if not messages:
        system_prompt = """You are a security profiler. Assess the target's type,
        connectivity, and data sensitivity, and recommend the most conservative safe
        execution mode. Use the available tools to investigate before concluding.
        When uncertain, lower your confidence and prefer isolation."""

        user_prompt = f"""Target input: {state['raw_input']}
        User-declared sensitivity: {state['declared_sensitivity']}
        User-declared regulatory flags: {state['declared_regulatory']}
        Target id: {state['target_id']}"""

        new = [SystemMessage(system_prompt), HumanMessage(user_prompt)]
        messages = new

    response = model_tools.invoke(messages)
    



    return {"messages": [*new, response], "retry": state.get("retry", 0) + 1}


def finalize(state: ProfilerState):

    messages = [
        *state["messages"],
        HumanMessage("Using the evidence above, produce the TargetProfile."),
    ]
    profile = model.with_structured_output(TargetProfile).invoke(messages)

    declared_sensitivity = state["declared_sensitivity"]
    declared_regulatory = state.get("declared_regulatory", [])
    
    profile = TargetProfile(
        **{
            **profile.model_dump(),
            "target_id": state["target_id"],
            "raw_input": state["raw_input"],
            "data_sensitivity": declared_sensitivity,
            "regulatory_flags": declared_regulatory,
        }
    )
    tools_msgs = [m for m in state['messages'] if isinstance(m,ToolMessage)]
   # a target counts as OBSERVED if any tool actually made contact with it.
    # ratio-of-errors doesn't work: deep_port_scan can never fail (it reports
    # {} open ports for a host that doesn't resolve), so it dilutes the ratio,
    # while tls_inspect against a plain-HTTP port errors on a target that was
    # seen perfectly well.
    SEEN = ('"status"',                    # deep_http_probe got a response
            '"tls_version"',               # tls_inspect completed a handshake
            '"languages_by_ext"',          # codebase_inventory walked the tree
            '"shape": "filesystem_path"')  # the path exists on disk
    reached = any(k in str(m.content) for m in tools_msgs for k in SEEN)

    if tools_msgs and not reached:
        profile.confidence = min(profile.confidence, 0.4)



    profile.recommended_mode = _select_execution_mode(profile)
    return {'profile': profile}

def should_route(state: ProfilerState):
    lm=state['messages'][-1]

    if state['retry']==10:
        return 'final'
    if getattr(lm, "tool_calls", None):
        return "tools"
    return 'final'



graph.add_node("llm_call", llm_call)
graph.add_node('toolsnode',ToolNode(tools))
graph.add_node('final_node',finalize)
graph.add_edge(START,'llm_call')
graph.add_conditional_edges('llm_call',should_route,{

    'tools':'toolsnode', 'final':'final_node'
})

graph.add_edge('toolsnode','llm_call')
graph.add_edge('final_node',END)

app=graph.compile()
app