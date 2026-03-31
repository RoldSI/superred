Proposal
Project hypothesis
Facilitating AI system red-teaming to improve the threat-model aware evaluation of AI systems, promoting strong defenses


Existing agent red teaming is fragmented across attack specific codebases, benchmark specific implementations, and narrow thread models
We modularize attacks, enabling AI system red-teaming improvements through (a) the discovery new combinations of existing components and (b) the quick development of new powerful strategies,
which enables thorough evaluations of AI systems though (a) flexible and strong threat models, providing (b) easy-to-use red-teaming as a service


We build a framework for comprehensive red-teaming of AI systems that is easy to use for red teamers and AI system developers. Present evaluation of AI systems is limited by the inaccessibility of portable comprehensive red-teaming The framework is easy to use and provides red-teaming as a service
The framework flexibly instantiates (strong) threat models over observables, controllables, feedback, and budget and enables modular attacks. Existing attacks are restricted to a single technique and narrow threat models each
The framework is highly modular, enabling rapid progress in red-teaming strategies by making concept and strategy implementations accessible and re-combinable outside of code silos
Project timeline


Deadline
	Milestone
	20 March
	Framework conceptualization
	3 April
	Implement barebone framework
	10 April
	Implement existing targets (real world + benchmark) as modules
	10 April
	Implement existing red-teaming strategies as modules
	17 April
	Evaluate existing policies on existing targets
	17 April
	Implement custom red-teaming strategies
	24 April
	Evaluate custom red-teaming strategies
	1 May
	Writeup
	

	Implement additional framework features
	6 May
	Submit to NeurIPS
	Team
Lead: Simon, Zhun
Members: Rishabh Sinha, Sarthak Munshi
Workplan
CW12
Goal: Refine framework design principles and start formal framework specification to make explicit the details


* Specify interface A (target_module_interface) using python protocols
* Specify interface B (target_module_security_claim_interface) using python protocols
* Specify interface C (optimizer_interface) using python protocols
* How to implement (target) proxies (with no(?) target modifications)? In particular
(a) How to intercept tools/injection points of target modules, even if not easily exposed (should be MCP based, preferably, for compatibility with agentbeats)?
(b) How to proxy LLM calls if not directly exposed by a target?
* Consider formalized LLM security (existing paper draft from separate project) to determine if there is a nice structure/abstraction for security claims


Rishabh
* Refine threat models based on comments. Specifically, make more specific and work out details
* Refine traces with more details
Develop a precise and exact structure, justifying every component
In such a way that’s defendably exhaustive, while having a minimalistic abstract structure
+Is there a way to work out valuable provenance information from the proxies only? If we can’t do better than putting it into an LLM to get an analysis, we can also just omit doing that. The optimizer can do if it desires if we just provide the timestamped linear trace (?)
* Formal(ish) argument for optimality of optimizer/target design
@Zhun: You probably have the most context and can say/see if this is feasible given existing theory and characterizations of attackers etc.
Can we show that this design can cover the entire computationally possible design space? If not, can we make small modifications to make this possible?
Idea: Prevent this being “just another” arbitrary framework, instead this being the final framework


Starthak
* Evaluation
- Think through which specific analysis/combinations of control variables across the dimensions (target, attack, threat model) we want to do
- Doing literature review to find specific sota targets for families/defenses and and sota attacks for attack types. Also look at all popular attacks/targets and add appropriate categories if they are not covered
- Think if additional/other metrics would be interesting
Threat model: Design scenario where this framework could be successful
- general personal assistant (OpenClaw)
- coding agents (Gemini-CLI, …, opencode, ? which coding agent is good for testing)
- web agents
- deep research agents
* Existing modular attack
- Doing literature review to find existing attack(s) that are presented as a monolith but internally can be decomposed into modules corresponding to our optimizers
- Intention: We can implement them and substitute its modules, showing there are great improvements possible just through (re)combination


Sure
* Staged running
We want that optimizers can iterate on a specific injection point without continuing to run the agentic AI system. Think about how to achieve this and integrate it into the framework design by utilizing the LLM proxy
* Target modules
Split of the security specification (= tasks + verifier). Can we do this so that claims and tasks are transferable between targets? (Maybe not as specific tasks are quite specific to the capabilities of an agent?) Would split it off nevertheless, as it allows testing different security claims on a target AI system
* Budget
- Elaborate and work out details for the part of the optimizer interface for budget estimations. Which inputs does it get? How does it estimate budget? Propagate budget estimation through sub-modules? How to do estimation before and provide new estimation while running?
- Actually allow for budget control? Or rather just run and observe used budget? Make budget control an optional feature of an optimizer?
- Budget control (prob.) not necessary
* Benchmark perspective on framework
Benchmarking red teaming strategies. Benchmarking target systems
* Integration with AgentBeats, especially in the face of running benchmarks
* Declarative use in AI system (easier for AI system developer) vs. Imperative wrapper around AI system (easier for red teamers)
Possibly both possible?
* Look at https://www.promptfoo.dev/
________________


CW11
Goal: Refine framework design principles and specification, and its evaluation


Please define the target/optimizer interface using the A2A if possible. (MCP for tool proxies possible?) This would facilitate integration with external systems, such as AgentBeats
Modules should be python modules primarily, just interface A2A style


We can collect results in the paper outline. Feel free to propose new/different sections etc.


* Full module interface specification (following A2A)


Rishabh
* Formalize threat models
Consider security domain (usings tags) instead of classical white/grey/black (?) Maybe closer access scopes that are available in real setups
Formalize in paper draft and make consistent among conceptual design and structure implementation so that it references the formalization
* Traces (& observables)
- How to represent traces and agent trajectories (for the implementation)? Which observables, and in which format exactly to specify them? Consider how conversion into the representation for each target system would work
- Consider standards (example) for agent trajectories
* Read through the paper outline and freely add Google Docs comments/edit suggestions


Starthak
* Evaluation
- Think through which specific analysis/combinations of control variables across the dimensions (target, attack, threat model) we want to do
- Doing literature review to find specific sota targets for families/defenses and and sota attacks for attack types. Also look at all popular attacks/targets and add appropriate categories if they are not covered
- Think if additional/other metrics would be interesting
Threat model: Design scenario where this framework could be successful
- general personal assistant (OpenClaw)
- coding agents (Gemini-CLI, …, opencode, ? which coding agent is good for testing)
- web agents
- deep research agents
* Existing modular attack
- Doing literature review to find existing attack(s) that are presented as a monolith but internally can be decomposed into modules corresponding to our optimizers
- Intention: We can implement them and substitute its modules, showing there are great improvements possible just through (re)combination
* Budget
- Elaborate and work out details for the part of the optimizer interface for budget estimations. Which inputs does it get? How does it estimate budget? Propagate budget estimation through sub-modules? How to do estimation before and provide new estimation while running?
- Budget control (prob.) not necessary
* Read through the paper outline and freely add Google Docs comments/edit suggestions


Zhun
* How to implement (target) proxies (with no(?) target modifications)? In particular
(a) How to intercept tools/injection points of target modules, even if not easily exposed (should be MCP based, preferably, for compatibility with agentbeats)?
(b) How to proxy LLM calls if not directly exposed by a target?
* Formal(ish) argument for optimality of optimizer/target design
@Zhun: You probably have the most context and can say/see if this is feasible given existing theory and characterizations of attackers etc.
Can we show that this design can cover the entire computationally possible design space? If not, can we make small modifications to make this possible?
Idea: Prevent this being “just another” arbitrary framework, instead this being the final framework
* Target modules
Split of the security specification (= tasks + verifier). Can we do this so that claims and tasks are transferable between targets? (Maybe not as specific tasks are quite specific to the capabilities of an agent?) Would split it off nevertheless, as it allows testing different security claims on a target AI system
* Read through the paper outline and freely add Google Docs comments/edit suggestions


Sure
* Look at https://www.promptfoo.dev/
* Staged running
We want that optimizers can iterate on a specific injection point without continuing to run the agentic AI system. Think about how to achieve this and integrate it into the framework design by utilizing the LLM proxy
* Benchmark perspective on framework
Benchmarking red teaming strategies. Benchmarking target systems
* Integration with AgentBeats, especially in the face of running benchmarks
* Framework design finalization
Declarative use in AI system (easier for AI system developer) vs. Imperative wrapper around AI system (easier for red teamers)
Possibly both possible?
* Read through the paper outline and freely add Google Docs comments/edit suggestions
Paper
1. Introduction
Diagram overview
  

This shows the overall system, comprising a target module with security specification, a zcontroller, and a graph of optimizer modules. The interface between the optimizers is the same as between the controller and optimizer (not shown for visibility)




  

This shows just the optimization loop for which the controller/target system can be abstracted. The input and static configuration depend on the threat model. The inputs include the latest result, traces etc. The controller takes care of running the target module for provided controllables
  

Compare related work based on the overview
2. Related work and background
AAA (agentified agent assessment)
Build upon it → A2A and MCP
Potential for compatibility, although we choose a different runtime for practicality and ease of use in security context. But offer export functionality to obtain agentbeats green agents from optimizer (?)


https://www.promptfoo.dev/
Provide a structure to integrate testing into workflow and make insights visible. How we are better: Promptfoo focusses on evaluation and testing for target systems. But it does not consider strong threat models nor facilitates red-teaming
* We consider different threat models (programmatically) while promptfoo does not naturally distinguish different threat models
* Our red-teaming provides an environment for reusability and composability of attack strategies and approaches
* Their focus is more on vulnerability families and evaluating targets. We further prioritize the development of strong red-teaming strategies
* Their target system integration is relatively narrow, focussing mostly on accessing them through external APIs. Being useful for application testing, we also allow even stronger integration for even stronger threat models
* Some promptfoo features only work using Promptfoo Cloud, while we support local running
* We provide stronger control and mocking of the environment, which allows stronger access, observability, and threat models
* We encourage comparison between red-teaming strategies via an arena for tracking
3. Framework design principles
Facilitating AI system red-teaming improvements to improve the evaluation of AI systems, promoting strong defenses


Focussing on both red-teamers and AI system developers. Prioritizing one doesn’t work because the usefulness depends on usage from both groups
Flexible & strong threat models
to obtaining meaningful insights in AI system security


Presently used white/grey/black box taxonomy inflexible and too coarse
More flexible separation between interfaces, injection points, information sources, … - split into security domains using tags
To better match real agent stacks


Only strong threat models yield meaningful insights on the security of AI systems. Benchmarking with threat model favorable for test scenario provides limited information
Allow the evaluation of red-teaming strategies on AI systems that automatically explores various (strong) threat models for that target AI system


A target AI system is defined as exposing: O as observables/traces (part of inputs), C controllables, F is feedback/judge assessment (part of inputs)
Controllables are interfaces/injection points. Feedback is information that is provided from the task evaluator and not generated by the target system. Observables comprise all information generated by the target system (including code, traces, …)
Each item i in O, C, or F is assigned a tag d(i) drawn from a domain vocabulary D. A vocabulary allows for target specific tags but should include at least user, external_data/tool, internal_data/tool, tool_catalog, internal_context, memory, model, verifier, and code


Threat model M then becomes budgeted access profile M = (C, O, F, B), where C, O, and F are subsets of interfaces from I made available to attacker as controllables, observables, and feedback channels, and B specifies budget constraints such as maximum iterations, model calls, tokens, wall clock time, or monetary cost
A threat model corresponds to a subset for each of the four components
in this formulation, black box is a special case in which O and F are intentionally small and C is usually restricted to user or external_data surfaces, for instance


This allows for classification of emerging interoperability protocols (MCP, A2A, …) but also custom interfaces
we evaluate under family of threat models induced by selective exposure of tagged interfaces. concretely, target adapter exports strongest available interface, and controller instantiates weaker threat models by restricting which tagged controllables, observables, and feedback channels are passed to optimizer
this is right level of abstraction for today’s frontier because strongest attacks are increasingly adaptive and interface specific rather than tied to single monolithic access assumption
recent work explicitly argues that robustness claims made only against static or weak attacks are misleading, and shows that many recent defenses can be bypassed once attacker is allowed to adapt its optimization strategy to defense
Easy development of new powerful strategies
by allowing (a) the easy development new red-teaming strategies and (b) re-using existing components from previous work for quick progress


Enabled through optimization-centric modularity. Attacks are abstracted as optimizations (for some adversarial outcome). Covers all existing attacks
Attacks can optimize at different abstraction levels (single prompt, full system) and can, thus, be re-used as modules


Allows for interpretability of attacks, leading to better understanding and progress
Ease of use/red-teaming as a service
to commoditize thorough security analysis of AI systems


Given target system: should be very quick to run evaluation using various attack strategies under various threat models, obtaining easy-to understand quantitative insights
Portability of red-teaming strategies across target systems: should be very quick to run on various popular target systems and benchmarks, obtaining quantitative comparison to other attacks
- no (or minimal?) modifications to the target AI system should be necessary for easy of use


This can be understood also as a benchmark. By varying the optimizer on one target (understood as a benchmark), one can evaluate red-teaming strategies in depth. This includes seeing how their performance compares under different threat models, foundation models, etc.
By varying the target for a given powerful red-teaming strategy, one can compare different AI systems’s security under varying threat models
But this framework is not primarily focussed on benchmarking, the above is an interpretation of the setup. It is conceptually possible, however, to export a red-teaming strategy and/or a target system (for a fixed chosen threat model) into a unit that can then be exposed. This allows integration into agentbeats, for example


Transparency when running from cost perspective: cost transparency and estimation


Creating visibility for red-teaming success: Online arena with leaderboard of red-teaming implementations. Built upon agentbeats. Targets can be wrapped/exported in purple agent compatible format
Attackers can be exported as purple agents
4. Framework system design
Target module
Imperative wrapper around AI system: Abstracting the AI system into a standardized interface


This is a wrapper around the target that abstracts all the details of running and accessing the target. This simplifies the development of red-teaming strategies as red-teamers are not necessarily interested in implementation details of a particular target 
The details of the target are hidden and may involve running the system locally (Docker), or accessing a black-box remote system unsuitable for local running by API


Given a target repository, we use and provide an AI tool that automatically creates the wrapper


A target module exposes full access for a strongest-possible attacker. The framework orchestrator considers different threat models by only making a subset of the specified interfaces available to an attacker. To expose at the right granularity, all attack/injection points are tagged, where different tags correspond to security domains. User/internal tool/external tool are default options, but modules may use custom tags


Framework-exposed module specification:
* Observables/traces O
   * [required] system description
   * System code
   * Traces, post-execution
This is particularly relevant if there are internal runtime events not captured by any proxy
   * tagged (user/internal/external/...) for specification of security domains
   * Controllables (attack surfaces) C
   * System prompt
   * User input
   * [required] LLM proxy
   * [required] Tools proxy
proxy for each tool that may be poisoned (including description/documentation), each tagged as user/internal/external/…
      * [required] security specification / task + feedback/judge (=verifier) (properties the system aims to be safe against)
High-level description of the purpose of the system
Each below must also include a judge/evaluator
         * Direct attack security
Pairs of specific benign user goals/prompts and malicious attacker goals (incl. evaluator/judge) to be achieved given the benign user
         * Indirect attack security
Malicious attacker goals (incl. evaluator/judge)
         * Jailbreaking security
Specification of behavior that violates a safety property/claim
            * [required] required runtime params (LLM keys, ...)


Benchmarks can also be wrapped as a target module, and are then easily accessible to different red-teaming implementations


Target modules can specify to be multithreaded. Then k instances can be run at the same time and an optimizer can queue multiple attempts which may be evaluated in parallel if the target module allows for multiple interfaces
Running multiple interfaces is also abstracted by the module itself and may be implemented with many Docker instances of the same environment setup under the hood


Centralized target module repository → ease of user for red-teaming
Target modules can be automatically downloaded and used by the framework
observables/traces
represent every run as canonical event based trajectory to capture tool calling agents, retrieval augmented systems, multi agent protocols, and adaptive defenses
Model canonical trajectory based on OpenTelemetry GenAI conventions (?), OpenInference, and W3C PROV for provenance
trajectory should additionally reference a typed artifact store for large payloads, so that trace can carry text, JSON, images, files, etc.


observables defined as
(a) threat model specific projections of full trajectory. if T is maximal recorded trajectory and M is active threat model, optimizer receives O(M, T), where O is projection operator that filters events and fields by role and security domain tag. Why: implementation and semantic conformity making formalization very applicable and enforceable in implementation
(b) static information (code, system description, …)


Target runtime
Declarative framework for use in AI systems


Developers of an AI system insert framework decorators/callbacks/interceptors into the AI system code. This is focussed at AI system developers who want to evaluate their systems easily. Thus, this assumes familiarity with the AI system but requires no familiarity with red-teaming attacks


to support heterogeneous targets, each adapter implements a translation layer from native runtime artifacts into canonical trajectory schema
Why: optimizer is target agnostic, target-specific details hidden - general interface
Optimizer module
We conceptualize attackers (modules) as optimizers, who maximize some adversarial outcome


An optimizer module optimizes a goal (freetext and ) over a set of controllables. It does so while having access to a set of informative inputs, context, and internal state: 
The assessment of the judge always contains a final score that is only of comparative meaning, but may also provide subscores. The result during each iteration not only contains the optimizer output but also a cost estimation and observability/traces in each iteration


The inputs for a given AI system contains the judging result of the last iteration and varying information about the target system depend on the considered threat model. The framework controller limits available inputs to consider different threat models. The last iteration is represented as a tuple (input, output, evaluation, traces). The content of the traces also depends on the threat model
The context is also threat model dependent and may include system descriptions and code
The state content and evolution is determined by the module but may be built by a module to include the iteration history. Using the provided subscores, the optimizer can also model Pareto frontiers in its state


Further, an optimizer produces a flag that states whether it believes to have fully explored all it’s options and reached its best possible result


Optimizers exist as modules and can depend on each other. An existing red-teaming strategy may be implemented as a standalone optimizer. But optimizers may also implement general prompt optimization strategies not specific to an adversarial setting. Such can be used as sub-modules by other optimizers
Optimizers can then be visualized as trees/graphs, which allows for easy interpretability of modularized attack methodologies. We allow cycles for recursive policies but recognize that prohibiting cylces could enforce termination if individual optimizers terminate
(Plan: We don’t enforce anything during early development for simplicity/speed. But may later add)


We can distinguish optimizers based on their complexity, which is determined by the controllables. We consider -ary and -ary optimizers with a single or arbitrarily many controllables


An optimizer may not actually optimize itself but fully delegate optimization to sub-optimizers. This allows for simple implementation of meta-red-teaming strategies that combine existing strategies


Example
-- optimizer 1: FANCY NEW THING (input: DB, webserach, user query)
        |- opimitzer 4: optimizer_anything (input: websearch, output: injection suggestion, feedback: sucesss)
        |- optimizer 2: something_else (input: user query, DB, output: ...)
        |- opitmizer 3
	-- our optimizer (input: everything)
        |- existing sota 1 (input: everything)
        |- existing sota 2 (input: everything)
                |- ...
                |
        |- existing sota 3
	

An optimizer has an additional interface for cost estimation and budget. It can run in either mode: Iterating until the optimal is reached, or iterating until some budget is consumed
In budget mode: The budget is provided in input and output token counts. Once the budget is consumed, the iteration stops. When calling a sub-optimizer, and optimizer must allocate a share of its budget to the sub-optimizer. This is done with a budget entity which can spawn children whose sum can’t exceed its total budget
In estimation mode: The module provides a static estimation of #iterations and #(input/output)tokens/iteration, and updates values with each iteration. Those are propagated up the optimizer hierarchy to get high-level estimates. An optimizer can state it’s own estimation, when it uses sub-optimizers, their estimations are automatically added
Further, the actual cost of an optimizer is tracked by means of an LLM proxy. Multiple API keys may be used to split cost tracking if the API does not provide cost results for each request individually


Optimizers generally run one iteration at a time and may be interrupted by their parent at any time. Only the highest level optimizer is run until it states to be finished
But naturally one can manually run a child until it states to be finished, as this will be common it is provided by the library


benefit of described threat model formalization is that it makes optimizer abstraction threat model agnostic. it receives whatever C, O, F, and B controller exposes for active threat model and optimizes accordingly. this aligns with broader shift in recent optimization work toward declarative, modular evaluators and reusable search operators, as seen in GEPA, optimize_anything, and promptolution. these systems differ in scope, but they all reinforce same design lesson, optimization modules are most reusable when interface cleanly separates artifact being optimized, evaluator, and diagnostic side information returned by evaluation.


Centralized optimizer module repository → ease of use for AI system developers
Centralized seeding repository
Would be against it now actually because of the insight: low diversity in attack paths
This would also strengthen weak attacks by being given the answer essentially. We would not compare how good different models actually are but rather see how good they could apply the result of the best strategy
Runtime/controller
The controller builds different threat models that are evaluated. It uses the user/iternal/external/… tags to group inputs and traces, and runs the optimizer for user, user+internal, and user+internal+external, and other combinations


The controller is implemented as an optimizer itself


Staged running
Don’t run the AI system from the beginning but instead continue from one place with different items inserted for a placeholder. The goal is to iterate faster without rerunning the entire AI system


LLM model proxy (attacker)
Change the used LLM as a free variable and provide observability of cost and LLM traces for each optimizer


target AI system proxies
LLM model proxy (target AI system)
Change the used LLM as a free variable
Create the trajectory/trace by recording LLM input and output
Enable staged running by replaying the trajectory/trace to a certain point (requires that AI system deterministic except the proxied input/output)[a][b]


Tool model proxy (target AI system)
Relevant for trajectory/trace and staged running
Injections can be modeled as modifications to the proxied content: Every external interaction can be poisoned. Intercept points are tagged by security domain (user/internal/external/…)


Those proxies also allow the use of centralized API keys
Running
Staged running
Standardized evaluation
5. Implemented modules
increasing complexity; first basic prompt optimizer, then more sophisticated overall optimizer that uses previous; then one that dynamically build dependency tree at runtime
Attacker modules
Benchmarks and most popular AI systems
Utility modules
Prompt optimization (fuzzing)
Existing red-teaming strategies
Meta-attacker[c][d]
Simple
Do one strategy until optimal, then go to next and have it improve, …
Iterate until tried every single one again without yielding improvement
6. Evaluation
Control variables for evaluation
Targets
Families by functionality
web agents
coding agents
RAG agents
By defenses
PromptArmor
Progent
MELON
Structured input defenses (StruQ/SecAlign)
Attack families
prompt mutation/fuzzing
reflective optimizer
RL-style search
meta-composition
Threat models (by security domains; consider user, user+internal, user+internal+, user+external, user+internal+external, user+internal++external)
User: +system description+user injection
External: +external tool injection
Internal: +system specification+traces+internal tool injection
Internal+: +system code


Comparison metrics
ASR
utility degradation
cost/successful attack
Time to first successful attack
Simplifies development of SOTA red-teaming algorithms & strategies
Show that modularity actually helps with implementing/building better algorithms more efficiently
(a) Consider new 'meta'/composed attacks
(b) See if there is an existing attack where a sub-module can be identified. Maybe we can take the existing and just substitute the sub-module from the authors and improve upon their work then?


Showcased through implemented strategy: how existing things were reused, and showcasing quantitatively how it beats existing solutions
Comparison of red-teaming implementations across threat models
For a fix target each


	Red-teaming 1
	Red-teaming 2
	Red-teaming …
	Threat model 1
	

	

	

	Threat model 2
	

	

	

	Threat model …
	

	

	

	Here we can compare to the authors results. I.e. show how this quickly provides a more comprehensive assessment
Comparison of red-teaming implementations across targets
Performance of meta-strategy
Focus on composed attacks vs standalone baselines (under matched budgets)
Benchmarks targets easily and consistently
Case study for complex agent systems (e.g., openclaw)
7. Comparison to existing work
Agentbeats for benchmarking/evaluation
  

We also eval using real-world stuff by cross applying extensively; not manually created artificial benchmarks
8. Discussion and conclusion
Statements
Use of AI
Ethics
Future work
This framework can also be used to implement strategies to identify attack vectors. The optimization output (currently an exploit) would be substituted by an attack vector
Related Works
It’s good to go through Dawn’s talk: https://www.youtube.com/watch?v=CvZDJxd4LKM


Especially the exploration space:  
and the design space:
  




Different threat models:
            * different interfaces for the agent adapters -> scorer module


Compare with AgentXploit:
            * AgentXploit:
            * red-teaming part relies on LLM reasoning, agent to reason how to optimtize the adv prompts.
            * white-box threat model
            * require attack path analysis
            * Super Redteaming:
            * abstract existing redteaming strategies -> discover new combination of different components, develop new red-teaming algos…
            * cover different threat models
            * make it easy-to-use, redteaming as a service
            * a good platform for developing new red-teaming algos






A good starting point of understanding the different attack strategies and current SOTA defenses:
[2510.09023] The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against Llm Jailbreaks and Prompt Injections


Prompt Optimization
Paper
	Method
	Note
	https://gepa-ai.github.io/gepa/blog/2026/02/18/introducing-optimize-anything/
	declarative LLM optimization framework for text-serialized artifact using score + ASI diagnostics and Pareto frontier search
	target: code, prompts, agents, configs, policies, SVGs, solvers
ASI: logs, errors, outputs, runtime, images. generation: reflection-driven targeted edits
claimed results: strong gains on coding-agent skills, cloud routing/scheduling, ARC-AGI, AIME, CUDA kernels, circle packing, and blackbox optimization
	[2512.02840] promptolution: A Unified, Modular Framework for Prompt Optimization 
	framework for discrete prompt optimization with interchangeable LLM/Predictor/Task/Optimizer components and includes OPRO, EvoPromptGA/DE, CAPO
	positioning: low-abstraction, extensible, non-invasive alternative to monolithic frameworks ex. DSPy
tasks: classification, judge, reward where use cases: existing pipelines, optimizer benchmarking, reproducible studies
results: CAPO best on both GSM8K 93.7 and SST-5 56.3 in comparison
	[2507.19457] GEPA: Reflective Prompt Evolution Can Outperform Reinforcement Learning
	reflective module-prompt optimization for compound LLM systems via LLM reflection on rollout/evaluator traces; Pareto-frontier sampling over candidates
	target: multi-module agents/workflows with fixed weights. 
feedback: reasoning, tool traces, compiler/rubric text 
results: beats GRPO with far fewer rollouts and beats MIPROv2 / TextGrad / Trace on reported benchmarks
	[2406.11695] Optimizing Instructions and Demonstrations for Multi-Stage Language Model Programs
	MIPRO for LM programs: jointly optimizes module instructions + few-shot demos under only task-level supervision; proposals via grounded instruction generation and bootstrapped traces, credit assignment via Bayesian surrogate
	target: multi-stage DSPy-style LM pipelines with no module labels / gradients / logprobs. 
proposal: dataset summary, program summary, demos, prompt history, tip credit assignment: surrogate beats greedy/history-only variants in general. results: MIPRO best on 5/7 tasks, up to +13% accuracy
	Optimizing Generative AI by Backpropagating Language Model Feedback
	TextGrad: textual backprop framework for black-box generative systems treats prompts, intermediate outputs, final solutions, code, molecules, treatment plans as optimizable variables in a computation graph
	core idea: replace numeric gradients with natural-language critiques propagated through arbitrary functions and tool chains
works for: prompt optimization, test-time solution/code refinement, multi-module agents, multimodal systems
results: LeetCode Hard 36% vs 31% Reflexion, GPQA 55.0%, GSM8K prompt opt 80.8%, object counting 91.9%
	





Attacks
Paper
	Method
	Note
	[2307.15043] Universal and Transferable Adversarial Attacks on Aligned Language Models 
	Gradient-based
	goal: universal jailbreak suffix 
setting: white-box optimize, black-box transfer. eval: harmful-string exact match + harmful-behavior ASR 
results: Vicuna-7B 88% string exact match, 99% behavior ASR, universal 100/98 train/test
	[2310.04451] AutoDAN: Generating Stealthy Jailbreak Prompts on Aligned Large Language Models 
	Genetic + gradient
	focus: automated stealthy jailbreaks 
strengths: high ASR, better cross-model transfer and cross-sample universality, strong against perplexity-based defenses
key result: large gains over GCG on Llama2 and after defense, while keeping low perplexity / readable prompts
	When LLM Meets DRL: Advancing Jailbreaking Efficiency via DRL-guided Search 
	RL-based
	core idea: jailbreak = sequential search problem
state: current prompt embedding. action: pick mutator
reward: semantic similarity between target response and a reference harmful answer. claim: more effective and less random than GA / in-context attacks. results: beats PAIR, Cipher, GPTFUZZER, AutoDAN
	[2510.04885] RL Is a Hammer and LLMs Are Nails: A Simple Reinforcement Learning Recipe for Strong Prompt Injection 
	RL-based
	goal: stress-test prompt-injection defenses like Instruction Hierarchy and SecAlign with stronger automated attacks
reward: binary / soft tool-execution success from target model outputs
strength: achieves high ASR on defended commercial models, including reported 98% on GPT-4o and 72% on GPT-5
	RL-based Red-teaming Agent for LLM Privacy Leakage | OpenReview 
	RL-based
	goal: unified automated red-teaming for system prompts and memorized training data / PII more guided than fuzzing/genetic search in black-box settings
results: beats handcrafted prompts, PromptFuzz, ReAct-style prompting, and white-box PLeak on many system-prompt extraction settings
	[2505.05849] AgentVigil: Generic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents
	black-box optimization, genetic method
	threat model: black-box
target system: web agent, coding agent, general agent
-> no assumption for the target system


scoring: binary feedback;
adv. sample generation: llm-based, based on general mutators
	[2602.20720] AdapTools: Adaptive Tool-based Indirect Prompt Injection Attacks on Agentic LLMs
	adaptive IPI framework with two pieces, adaptive strategy construction + attack enhancement via task relevant tool choice
	threat model: black-box IPI via tool outputs (plus optional grey-box MCP controller) 
target system: tool-calling LLM agents (web, coding, general) 
-> no assumption on agent/toolset 


scoring: binary success if target tool is invoked (ASR; also UA drop) 
adv. sample generation: LLM-generated adaptive prompts from a strategy library + task-aligned tool selection (Markov + embedding similarity)
	[2512.09321] ObliInjection: Order-Oblivious Prompt Injection Attack to LLM Agents with Multi-source Data
	new objective for multi-source inputs where attacker controls only some segments and does not know segment order. Uses order oblivious loss + orderGCG optimizer
	threat model: attacker controls subset of sources and contaminates 1 segment and does not know segment ordering in the final prompt (multi source order uncertainty) 
target system: LLM apps and agents that concatenate multi source segments (review and news summarization, RAG QA, tool selection) 
-> no assumption about ordering strategy or access to other segments 


scoring: binary success if output matches injected response across permutations (ASR averaged over segment orderings) 
adv. sample generation: gradient based segment optimization using order oblivious loss (expected CE over random permutations with LLM synthesized shadow segments) + orderGCG (GCG style token search with accumulated loss + beam buffer) to produce order robust contaminated segment
	[2507.14799] Manipulating LLM Web Agents with Indirect Prompt Injection Attack via HTML Accessibility Tree
	embeds “universal adversarial triggers” into webpage HTML that hijack agents that parse via accessibility tree. Uses GCG and demonstrates targeted and general attacks
	threat model: black-box IPI where attacker controls some webpage HTML that gets ingested into agent prompt via accessibility tree 
target system: LLM web navigation agents that parse pages through HTML accessibility tree (BrowserGym style action space with click scroll fill etc) 
-> assumes only that HTML is included in prompts and actions are executed from model outputs 


scoring: binary success if agent emits the attacker target action string that passes syntactic filter and gets executed (reported ASR + ASR verbatim vs executed) 
adv. sample generation: gradient based universal trigger search in HTML using GCG (extended to optimize one trigger over many prompt contexts goals for website or across websites)
	[2504.19793] Prompt Injection Attack to Tool Selection in LLM Agents (ToolHijacker)
	prompt injection aimed specifically at the tool selection pipeline. injects a malicious tool document into tool library to bias retrieval + selection. Formulates crafting as optimization with two phase strategy
	threat model: no-box tool selection poisoning where attacker injects one malicious tool document into an open tool hub library, without access to target queries retriever LLM tool library contents or top-k 
target system: LLM agents with two-step tool selection (retrieval with dense embeddings + LLM selection over retrieved tool docs) 


scoring: binary success if the malicious tool is selected for the target task across paraphrased task descriptions (ASR); plus retrieval stage inclusion of the malicious doc (AHR) 
adv. sample generation: optimized malicious tool description split into R and S R optimized to maximize retrieval similarity to the target task (LLM synthesized or HotFlip gradient over shadow retriever embeddings) S optimized to force selection once retrieved (gradient free tree-of-attack style LLM refinement with beam pruning or gradient based token optimization with alignment + consistency + perplexity losses)
	

Defenses
Paper
	Method
	Note
	[2507.15219] PromptArmor: Simple yet Effective Prompt Injection Defenses
	two-stage input guardrail contamination detection + removal. Uses off-the-shelf LLMs + fuzzy matching to strip malicious instructions.
	defense goal: detect and remove injected instructions from untrusted agent inputs before backend LLM acts, while preserving task utility 
protected system: LLM agents or apps that ingest external content (tool outputs, webpages, emails) where injections can appear -> drop-in guardrail layer, no changes to agent or backend LLM required 
core method: prompt an off-the-shelf guardrail LLM to output Yes or No for injection and, if Yes, extract injection span; then delete it from input using fuzzy matching 
evaluation signal: detection quality (FPR and FNR) plus end-to-end agent robustness after sanitization (UA and resulting ASR on AgentDojo, including adaptive fuzzing attacks)
	[2504.11358] DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks
	game-theoretic detector models interaction between attacker and defender to stay robust against adaptive threats.
	defense goal detect prompt-injection contamination in untrusted inputs before agent acts, with near zero false alarms and strong adaptive coverage protected system LLM agents apps that do instruction plus external data like web pages or tool outputs 
core method game-theoretic known-answer detection with a fine-tuned detector LLM prepend secret-key instruction missing key => contaminated minimax training inner max crafts adaptive injections that evade detection and still hijack backend task outer min fine-tunes detector to fail on injected inputs but pass clean ones GCG for inner max QLoRA gradient updates for outer min 
evaluation signal FPR on clean FNR on attacked across many tasks and attacks near 0 FPR near 0 FNR except when injected task equals target task adversarial example regime
	[2402.06363] StruQ: Defending Against Prompt Injection with Structured Queries
	structured queries force separation between trusted instructions and untrusted data via schema fields.
	defense goal make LLM apps robust to prompt injection by forcing instruction data separation protected system LLM integrated apps that concatenate developer instruction plus untrusted text 
core method structured queries with two channels prompt vs data secure front end encodes with reserved delimiter tokens and filters delimiter like strings structured instruction tuning trains a base model to follow only prompt side and ignore data side instructions using clean plus injected training augmentations 
evaluation signal attack success rate across many manual and optimization attacks plus utility via AlpacaEval manual ASR driven near 0 with little utility loss still partial vs strong optimized attacks TAP and GCG so not worst case secure
	[2504.11703] Progent: Programmable Privilege Control for LLM Agents
	programmable privilege control runtime tool-level enforcement using a specific policy language for allow/forbid actions.
	defense goal prevent agent hijacks by enforcing least privilege on tool calls so indirect injections and poisoned context cannot trigger unsafe actions protected system LLM agents with toolkits and external observations plus memory or KB where attackers can inject instructions or add malicious tools core method Progent is a runtime tool call gatekeeper with a policy DSL policies allow or forbid specific tools and argument patterns, ordered by priority on block it triggers deterministic fallback actions and can update policies dynamically based on agent state implemented as wrappers around tools using JSON or JSON Schema style policies 
evaluation signal utility on benign tasks plus attack success rate on AgentDojo ASB and AgentPoison reported ASR goes to 0 percent with near unchanged utility and negligible runtime overhead LLM assisted policy generation per user query reduces ASR a lot but not always to zero so manual policies give provable guarantee
	

	

	

	





Benchmarks
Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents
GEPA Interface Design 


gepa is reflective optimization framework for text serialized artifacts across code prompts agents configs and policies. the main design win is abstraction boundary. everything target specific lives behind adapter interface while the optimizer engine stays target agnostic. in practice they implement evaluate to run the candidate on a minibatch and return scores + traces and per objective subscores, and implement make_reflective_dataset to convert those traces into the structured feedback that a reflective proposer uses to generate targeted edits.
class GEPAAdapter(Protocol):
   def evaluate(self, batch, candidate, *, capture_traces: bool) -> EvaluationBatch: ...
   def make_reflective_dataset(self, candidate, eval_batch, components) -> dict[str, list[...]]: ...
   propose_new_texts: ProposalFn | None
gepa’s evaluation interface explicitly separates scalar selection signals from diagnostic feedback. scores drive the candidate selection. trajectories and side info are for actionable traces such as logs errors tool traces or intermediate outputs that help with mutation. objective_scores enables multi objective optimization rather than collapsing everything into one scalar.
@dataclass
class EvaluationBatch:
   outputs: list[RolloutOutput]
   scores: list[float]
   trajectories: list[SideInfo] | None = None
   objective_scores: list[dict[str, float]] | None = None
instead of tracking a single best candidate gepa maintains a pareto frontier. this preserves candidates that each excel on different subsets of examples or objectives via frontier modes instance objective hybrid and cartesian. operationally it also provides composable budget and termination controls and callback based event system so tracking logging and dashboards do not couple to core loop.
for super red teaming gepa is relevant less for surface ui and more for interface design. the adapter boundary matches the need to support heterogeneous target agents and threat models under a single evaluation contract. the trace first design matches adaptive attacks that rely on refusal text tool call traces sanitizer outputs and execution logs as optimization feedback. pareto frontier tracking naturally supports multi target multi defense red teaming where success varies by threat model and objective and should not be averaged away.


Meeting Notes
Mar 19, 2026
Add DT-Agent


How we inject the attacks:
            * Environment -- step 1 --> Tool response – step 2 –> agent process the response – step 3 --> send to the model
            * step 1: We need to have some capabilities to control the environment
            * step 2: Need agent support to add adapters
            * step 3: Model proxy or agent support
            * Tianneng Shi how to modify the environment in DT-Agent


Ensure most of existing attacks can be implemented in the framework


AgentBeats: e.g., green agent as the target, 
March 17, 0800 PT
Rishabh, Starthak, Sure


Rishabh’s work
Really liked the formalized parts w/ tuples, operators, …
shorter/concise wording, no need to write that much
transferred key insights to the paper overview
double check that I got it correctly
Next: Look further into how to obtain those traces and how they look exactly, i.e., implementation details
Think more about tiers and claims/guarantees we can then give with the framework


Walkthrough of paper outline for understanding
Freely choose (a) own notes and I integrate, or (b) directly write into paper


Sarthak’s structure
Further ideas
- memory/trace compression / reduction (do in a way that allows optimizer to compress as it suits)
- choose simple optimizers at runtime (?), specifically different implementations of the same idea https://arxiv.org/pdf/2312.02119
- consider async optimizer (with eventloop)


Workplan
Add to repo, specify interfaces as python Protocols there
Develop interface specifications separately
At this point it’s about which fields, … etc. We will unify them as a next step


Next steps are captured in workplan
March 16, 0900 PT
Rishabh, Starthak, Sure


Intros


Past week progress
Diagrams
Feedback from Dawn
Design aspects


Cycles
Pro: allow for recursive optimizers
Con: simplicity, for efficiency maybe no cycles (?)




Define workplan for CW12
March 9, 0900 PT
Zhun, Starthak, Sure


Intro + skills + interests


Project alignment
Project hypothesis
Project concepts: target module/runtime, optimizer abstraction
Timeline


Way of working
comm + feedback
(regular) check-ins?
Weekly project overview


Insights from literature review (Rishabh, Starthak)
Does the framework design (as in the paper outline) work with all related work?


Design update from last meeting
- Staged running probably postponing (strong assumption/requirement on target system environment) → highlight as future work, do if time in the end (?)
Iterative loop before providing answer to the target system → then becomes feasible (i.e. this staging happens invisibly to the target AI system)
- Declarative for use in AI system vs. imperative wrapper (can do both, would start with latter for speed)


? Discuss Rishabh’s comments
Doing offline


Workplan/next actions
The Workplan tab has a list of framework design items we should think about further. We will split those in the team, think, and work on them until next week
The resulting ideas and design can be put right in the paper outline tab
Simon to propose assignment. Please say if you prefer


Project name
        To be discussed, Zhun will talk with Dawn about it


Next steps
            * Zhun will get feedback on the current design ideas from Dawn
            * Everyone to continue the discussion on the framework design via comments in the doc
            * Simon to add chart(s) detailing framework design and flow by Tuesday, 10 March, morning
            * Simon to propose an assignment for framework design aspects to further look into
            * Everyone to work on their framework design aspects until next week
The assignment is a proposal. Please say if you would like to move the topics around :)
Please propose alternatives/… if you think something about the design ideas/notes doesn’t make sense
March 4, 1000 PT
Zhun, Sure


Actions
            * Simon to copy Notion documentation to Google Docs for better collaboration
            * Zhun to create Slack channel for the team
            * To schedule weekly sync with the team
            * Continue reading related work
            * Refinding paper draft and framework design
            * Team to brainstorm and decide on system name for the framework




Sure's notes
Promptfoo inspiration
Security claim as generators/iterators. Those are then also composable to allow to represent abstract standards (compliance) and individual test cases
This allows for target-specific testcases and general testcases
Think about how to make certain testcases specific to one target? Or should everything be general??
One testcase also with different security domains/threat models? I.e., give different information on something? I.e., provide different hints?


How to use modularity? What other new attack methods can we think of?
Idea: Automatically combine optimizers to optimal attack
As optimizers can be freely combined, implement algos (i.e. MCT search) that explore optimizer combinations to find optimal one for a given target
How about inference between (sub-)optimizers?


Make ‘how to use’ explicit
Explicitly state steps to use for an AI system, and for someone with an idea of a red teaming strategy


How to modularize target runtime, i.e., create target module from target runtime?
Want to that runnable freely and independently, so need to package still in Docker? But then still send to injection points within Docker somehow…


Can somehow combine and work together with agentbeats?
Then we could only do fully encapsulated modules really; otherwise would have to rework the runtime (then we can do independently in the first place)
Question/thought: How would A2A be used to discover target (structure)?
Think would be difficult as no only understand agent interface, but also it’s internal/external resources could be poisoned, which are not naturally exposed via it’s A2A interface
Maybe
optimizer module exposes A2A interface, and are recombineable through standardized A2A interfaces (for 1-ary and k-ary one interface each)
Target module/runtime exposes A2A that specifies all injection points of an entire system. I.e., system abstracted as a single agent
The controller is the green agent
This would only require making targets and optimizers available as purple “agents”, i.e., units that expose the A2A interface - but don’t actually have to be agents
Think about whether could then use agentbeats trace stuff, metrics, … (?)
Does agentbeats have traces, model proxy for replay/staged running/…
Look at agentbeats code to evaluate code quality, flexibility, and performance
Target model
A2A for user interface
MCP used by green orchestrator to host proxies for the possible injection points
Understand functionality for “MCP proxy and access control” and “Environment container hosting (via MCP)”
If do with MCP proxy interceptor, wouldn’t know which tools may be used in advance, would we? Because of tool discovery…
Challenge would be to know all interception points…
Actually also consider as threat model: Attacker doesn’t know injection points upfrom and doesn’t know all available injection points. Can only observe which are queried and conclude from that that they exist
Reason against it: high complexity
To discuss with agentbeats: One green agent that does multiple benchmarks, depending on the purple agent. How to do so that can have multiple leaderboards for one green agent?


Benchmarking from both perspectives
Benchmarks the performance of red-teaming on various targets
Benchmarks the security of targets under various attackers
From Dawn
also for the redteaming API/box, we should think about how to use agent to build it; and itself can be a benchmark as well
Framework design


Declarative for use in AI systems:
Insert framework callbacks into AI system code at possible injection points


	Imperative wrapper around AI system:
Abstracting the AI system into a standardized interface


	Defenders would like modularization of attacks
—
Pros
Easier for AI system developers to evaluate at runtime (focus on AI systems developers)
Cons
More difficult development: Discovery of injection points at runtime makes
	Red-teamers would like modularization of targets
—
Pros
Easier for red-teamers when target is an abstracted module (focus on red-teaming researchers)
Cons
Requires creating wrapper for each target AI system
	Allow both?!


agent developer can start the process just by running the agent: Scoring (run the agent) → Optimize the injection → Scoring again (https://github.com/inclusionAI/AReaL/tree/main/examples/openclaw)
superred run […]
more attack developer centric or agent developer centric
callback from the targeted AI system into our framework
Rishabh's notes
03/17/206
formalizing threat models
recent agent security work makes clear that classical black box, grey box, and white box taxonomy is too coarse for modern AI systems. current attacks differ not only in how much information attacker sees, but in which interface attacker can control or observe, untrusted web or tool outputs in indirect prompt injection, malicious tool metadata in tool selection poisoning, multi source data segments under unknown ordering, runtime traces, policy layers, or even code and configuration. likewise, current defenses act on different surfaces, including input sanitization, contamination detection, and deterministic tool time privilege control.[e][f] useful framework needs to model access by security domain and interface surface, not only by single ladder of visibility.
Paper statement: define target AI system as exposing finite interface set I. each interface i in I is annotated with role r(i) in set {controllable, observable, feedback} and set of security domain tags d(i) drawn from domain vocabulary D. default vocabulary should include at least user, external_data, tool_catalog, internal_context, memory, model, verifier, and code[g][h], while still allowing target specific extensions. threat model M then becomes budgeted access profile M = (C, O, F, B), where C, O, and F are subsets of interfaces from I made available to attacker as controllables, observables, and feedback channels, and B specifies budget constraints such as maximum iterations, model calls, tokens, wall clock time, or monetary cost. in this formulation, black box is no longer primitive category. it is special case in which O and F are intentionally small and C is usually restricted to user or external_data surfaces.
this formulation better matches real agent stacks and emerging interoperability protocols. MCP standardizes how hosts, clients, and servers exchange tools, resources, and prompts over JSON RPC based protocol, which makes it natural substrate for modeling tool and resource level attack surfaces. A2A, by contrast, is task oriented and treats interaction as messages, tasks, and artifacts exchanged between agents, which makes it better suited to inter agent orchestration than to fine grained poisoning surfaces. for this reason, framework should use security domain tags to describe what attacker can touch, while allowing A2A style task interfaces at control plane and MCP style tool and resource interfaces at execution plane.[i][j]
paper should replace statements such as we evaluate under black box to white box threat models with language of following form. we evaluate under family of threat models induced by selective exposure of tagged interfaces. concretely, target adapter exports strongest available interface, and controller instantiates weaker threat models by restricting which tagged controllables, observables, and feedback channels are passed to optimizer. this is right level of abstraction for today’s frontier because strongest attacks are increasingly adaptive and interface specific rather than tied to single monolithic access assumption. recent work explicitly argues that robustness claims made only against static or weak attacks are misleading, and shows that many recent defenses can be bypassed once attacker is allowed to adapt its optimization strategy to defense.
one benefit of this formalization is that it makes optimizer abstraction threat model agnostic. optimizer need not be rewritten for user only, tool poisoning, or internal context settings. instead, it receives whatever C, O, F, and B controller exposes for active threat model and optimizes accordingly. this aligns with broader shift in recent optimization work toward declarative, modular evaluators and reusable search operators, as seen in GEPA, optimize_anything, and promptolution. these systems differ in scope, but they all reinforce same design lesson, optimization modules are most reusable when interface cleanly separates artifact being optimized, evaluator, and diagnostic side information returned by evaluation.
traces and observables
for implementation, framework should represent every run as canonical event based trajectory rather than as single prompt response record. this choice is necessary because frontier now includes tool calling agents, retrieval augmented systems, multi agent protocols, and adaptive defenses, none of which can be understood from only final answer. OpenTelemetry’s[k][l] emerging GenAI agent conventions and OpenInference both converge on this point by treating model calls, agent steps, tool invocations, and retrieval operations as structured spans in distributed trace rather than as free form logs. at same time, OpenTelemetry’s agent conventions are still marked as development status, so they are best used as interoperability target rather than as sole normative schema for framework.[m][n]
Paper statement: run produces trajectory T = <e1, …, en>[o][p], where each event ek contains at least event identifier, parent identifier, timestamp, actor, operation type, tagged security domain, typed inputs, typed outputs, and cost metadata[q][r]. operation type should be drawn from small canonical vocabulary such as user_input, system_context, model_request, model_response, tool_call, tool_result, retrieval_query, retrieval_result, memory_read, memory_write, verifier_input, verifier_output[s][t][u], and error.[v][w] trajectory should additionally reference typed artifact store for large payloads, so that trace can carry text, JSON, images, files, or other outputs without collapsing everything into raw strings. this is consistent with direction of current observability standards, which emphasize typed spans, structured payloads, token economics, and enough execution context to explain or partially reproduce stochastic behavior.
observables should then be defined as threat model specific projections of full trajectory, not as separate ad hoc object. formally, if T is maximal recorded trajectory and M is active threat model, optimizer receives O(M, T), where O is projection operator that filters events and fields by role and security domain tag. this matters because different settings may expose only final outputs and scalar judge score, or additionally expose tool traces, retrieval results, verifier rationales, or internal prompts. treating observables as projections of single canonical trajectory ensures that implementation and paper use same semantics, and it prevents threat model from becoming informal side condition rather than enforceable interface contract.
to support heterogeneous targets, each adapter should implement translation layer from native runtime artifacts into canonical trajectory schema. for example, wrapped benchmark, Dockerized agent runtime, MCP proxy, or direct API only system may all expose different native logs, but each can still be normalized into same event vocabulary. this is exactly kind of separation that has proved useful in recent modular optimization systems, where core optimizer is target agnostic and target specific logic is isolated in evaluator or adapter layers. it also matches structure of current agent benchmarks such as AgentDojo and ASB, which evaluate many task environments under common experimental interface even though underlying tasks, tools, and environments differ substantially.
for standards, best practical recommendation is to ground runtime representation in OpenTelemetry and OpenInference semantics, while using W3C PROV for provenance links[x][y] between artifacts, actions, and evaluators when provenance matters for security analysis. OpenInference already standardizes LLM calls, agent reasoning steps, tool invocations, and retrieval operations on top of OpenTelemetry, while W3C PROV gives mature model for representing which artifact was produced by which activity from which inputs. lets us state that framework adopts canonical trajectory schema compatible with current observability conventions and enriches it with provenance edges needed for red teaming, attribution, and replay oriented analysis.[z][aa][ab]
target interface should also distinguish three observability tiers[ac][ad]. base observability should require little or no target modification and include final outputs, verifier outputs, and any tool or model traffic already passing through proxies. proxy observability should add normalized tool, retrieval, and model call traces through wrappers such as MCP or model proxies.[ae][af][ag] instrumented observability should add optional internal hooks such as hidden state snapshots, planner decisions, or memory accesses. this tiered design is important because it lets framework make strong portability claims without pretending that every target exposes same internals. it also creates natural way to define stronger threat models without conflating them with mandatory instrumentation.
FROM SURE: maybe we can think about how to obtain those traces and what’s part of them exactly? Given we don’t want to modify the target system, can we construct the necessary traces just through proxies? How would a trace then look like?
Or is it necessary to modify the target system (?) although undesirable for strongest/most informative traces?


Soemthing else we may have to think about: How to scope traces and observables for sub-optimizer. That optimizer may only need a subset of the information and otherwise get confused/overwhelemed?
Answer maybe: This has to be done by the higher-level optimizer. It gets the full information and then needs to scope it down
Does this work with staged running then, though?


.[ah]


For trace/optimizer memory management:
https://mem0.ai/




03/20/2026
threat models
            * finalize formal threat model as interface based access profile instead of using black box grey box white box taxonomy -> define target as exposing finite interface set I -> each interface  should be annotated by role r(i) in {controllable observable feedback} and by security domain tags d(i)
            * make default domain vocabulary tighter and more exact -> justify it as minimum useful basis for modern agent systems -> at minimum distinguish user -> external_data -> tool_catalog -> internal_context -> memory -> model -> verifier -> and code -> also make explicit that memory means persistent or cross step state while internal_context means per run hidden context like system prompts planner state and hidden intermediate instructions
            * keep mcp and a2a out of formal definition itself -> should just be treated as realizations that can be classified using same tag based formalism not part of actual threat model definition
            * replace claim about black box to white box evaluation with -> family of threat models induced by selective exposure of tagged interfaces

traces and observables
               * specify canonical trajectory format for one run -> run should produce trajectory  where every event has minimum fields needed for identity ordering actor operation security tags payload and cost
               * treat observables as threat model specific projections of full trajectory not as separate ad hoc structure -> formally optimizer receives  where projection operator filters events and fields by role and security domain tag
               * make injections first class trajectory events or explicit annotations so replay attribution and staged running can cleanly separate attacker induced perturbations from normal target behavior
               * keep verifier outputs conceptually separate from target generated observables -> but still log verifier input and output as explicit trajectory events for reproducibility and inspection

proxy only traces and provenance
                  * work out portable default trace that can be generated without modifying target internals -> default assumption should be that model tool retrieval and verifier proxies emit tagged events directly into canonical trace
                  * define best effort provenance in proxy only setting from observable causal links like parent child model calls -> tool call chains -> retrieval edges -> and injected artifacts
                  * state this clearly too -> strong provenance is not always recoverable from proxies alone -> richer provenance needs instrumentation or native target support
                  * use that to define clean guarantee -> portable mode gives faithful observable provenance over proxied events only -> instrumented mode gives stronger causal provenance when target exposes more internals

observability tiers and claims
                     * collapse current discussion into simpler tiered story so does not feel fragmented -> base tier means minimal portability tier for opaque or lightly exposed targets -> proxy tier means external facing observability through model tool retrieval and verifier proxies -> instrumented tier means internal observability through runtime hooks like planner state memory reads and writes and hidden state snapshots
                     * make claim precise -> framework supports strong threat models when target exposes those surfaces while still giving portable baseline for opaque systems -> do not require strongest tier everywhere because that would kill portability

subtrace scoping and staged running
                        * specify that controller or parent optimizer is thing responsible for scoping full trace down before passing information to sub optimizer
                        * define subtraces as filtered views of canonical trajectory not as separate trace formats -> also check compatibility with staged running since replay substrate should operate on full canonical trace while optimizers may only receive restricted projected views

formal argument for optimizer and target design
                           * do not claim coverage of computationally possible design space in unrestricted sense -> instead make narrower within framework abstraction boundary any attack strategy that iteratively chooses values for exposed controllables as function of exposed observables feedback and budget can be represented as optimizer module or as composition of optimizer modules
                           * pair that with dual statement for targets -> any target system that can be wrapped into interface set and canonical trajectory can be evaluated under same controller semantics whether it is benchmark dockerized runtime mcp mediated agent or direct api system
                           * frame this as representational completeness relative to exposed interfaces not universality over arbitrary hidden computation
if proxy only provenance is too weak to support stronger causal claims, framework should expose timestamped tagged traces only, and leave richer provenance analysis to optimizer modules 
question for Zhun -> is representational completeness relative to exposed interfaces the strongest defensible theoretical claim here, or is there a stronger result we can make about optimality or coverage with small interface changes


Sarthak's Notes
  
[ai]


SIMON’S COMMENTS
I would not distinguish between “strategy orchestrator meta-optimizer” and other “optimizers”. To me, that difference is a post-mortem interpretation depending on how the optimizer works. But they are all the same kind of module
Maybe we could distinguish between ‘complex’ and ‘simple’ optimizers. I.e., complex ones that optimize a full system and simple ones that optimize a single injection? (In below diagram, we would have two variants of of the C interface then?)


Meta-optmiizer selects optimizers from repository
Talked with Zhun about doing this (at runtime). We felt that it is simpler to just have those dependencies as static dependencies for those key reasons as far as I remember (a) simplicity in implementation, (b) reproducibility, (c) more properties of the framework
Each module can be a real python module (in pip etc.)


You use a round loop for the optimizer, right? I would propose doing the loop along a line. What I mean:
  

The loop follows more naturally from an optimization loop thinking
Why I would favor the line:
- No information flow outside the loop (added with dotted lines in left diagram)
- Corresponds directly to import structure and how the orchestrator instantiates optimizer and target system to the right
- I don’t see a nice way to implement the flow of information from the lowest level optimizer to the target system. Pass target system instance around (to optimizers)? But how then filter for threat model?
But I think the underlying idea and concepts are similar




We probably have to think of how to formalize a security specification/claim. I.e., what do we evaluate against and how do we evaluate?






Updated high-level architecture draft based on your ideas:
  

[a]This is an important caveat, maybe something like serialized agent system state capture and injection at key decision node in trajectory. tool side effects are also points of consideration
[b]Agreee 👍
I am uncertain about how feasible this is to proxy all non-deterministic behavior. If a target AI system does not naturally expose non-deterministic behavior, proxying/controlling the trajectory would be tricky...
Probably we can do this in the implementation depending on time in the end as it doesn't really add functionality but just efficiency?
[c]budgeted controller over typed sub-optimizers
[d]Can you elaborate?
[e]We don't control the defense model, I think?
The target system can do as it wishes and doesn't expose it with the current design?
[f]Correct, we do not need to control the defense model, point is only that defenses act on different surfaces so threat model should describe which interfaces are exposed regardless of whether a defense is internal or opaque.
[g]What is your rational for exactly those? It would be great if we can have an argument for why this is exhaustive for everything that may occur
- What is the difference between memory and internal context, for example?
[h]this is not closed or exhaustive yet but can be default basis that covers common surfaces seen across current agents, Memory refers to persistent or cross-step state and internal_context refers to per-run hidden context -> system prompts, planner state, hidden intermediate instructions.
[i]Is this part of the threat model specification? That the framework uses MCP/A2A is an implementation detail, isn't it?
I think that being able to classify all possible interfaces (MCP, A2A, ...) using this tag-based formalization is important here (?)
[j]Yes implementation details, not part of threat model itself. I would keep the formalization protocol-agnostic then say MCP and A2A are example realizations that can be classified by same tag system.
[k]Would you recommend going with this? Do you think this standard is establishing itself? Or should we rather ensure we're just compatible if it becomes mainstream?
[l]I would not make OpenTelemetry normative, would say we are compatible with it and align where useful, while keeping our own canonical schema so we are not locked to still-evolving standard
[m]It may be worth going deeper into the details of how this can be done specifically. I.e., how do we get/how can we populate the traces exactly?
- How can we generate/obtain those traces if the target system doesn't provide them itself?
- Also, how can this work with our tagging? So that we can get a 'subtrace' that is restricted to a specific security domain and thus, may not contain everything
- Can we generate traces in this form using just our model and tool proxies?
[n]Yes, proxies are enough for a portable default trace. Model, tool, retrieval, and verifier proxies can emit tagged events directly, and restricted subtraces can be gotten by filtering the canonical trace by event type and security-domain tag
[o]How would you represent the information of which injections were performed? Would you include that in the trajectory?
[p]Yes, injections should be first-class trajectory events or explicit event annotations. That makes possible to distinguish attacker-induced perturbations from ordinary target behavior during analysis and replay
[q]Is this aligned/corresponds to/compatible with OpenTelemetry conventions?
[r]Broadly yes, event schema corresponds to spans plus attributes, though we would likely need a small security specific extension for attack surfaces, injected artifacts, and threat-model tags.
[s]I think we may have distinguished between observables/traces (target systme generated) and feedback (task/evaluator generated) at a different place?
Should we include verification statements here?
[t]Might actually make more/a lot of sense to do this way...
[u]agree they should stay distinct conceptually -> verifier outputs can appear in trajectory for reproducibility but in formal interface they belong to feedback channel rather than target-generated observable channel.


i think so too -> logging verifier input and output as explicit events gives cleaner semantics and makes evaluator behavior inspectable without collapsing everything into a single scalar score.
[v]- I would be great to have an argument for why we choose a certain set of attributes
- Maybe we can structure this so that we don't have a long list but more abstraction that makes it easier to understand?
[w]Yes, would present this as minimal event schema rather than long list. Each event only needs identity, ordering, actor, operation, security tags, payload, and cost to support replay, filtering, attribution, and budgeting
[x]Why those exact? Which are alternatives and how are they inferior?
[y]strongest combination of observability compatibility and provenance modeling. main alternatives are ad hoc logs or benchmark specific traces are weaker as do not compose cleanly across heterogeneous systems or standard tooling.
[z]Similar to question elsewhere: Can we generate this (from proxies?), assuming the target system does not generate it in this format itself? I.e., practical consideration
[aa]Specifically for provenance also: How do we obtain provenance/causality information if the target system doesn't expose it?
[ab]yes adapter should normalize native logs or proxy observations into the canonical schema even when the target does not emit directly


best effort provenance by default from observable causal links such as tool call chains, model call parents, and injected artifacts. Stronger provenance requires instrumentation or native target support (enriched tier).
[ac]Do you see a way to make this less fragmented? If we have different options for various aspects in the framework, things become very fragmented?
I am thinking that if we want to claim to have strong threat models and 90% of target systems don't expose internals, we may not actually live up to the claim
Maybe require the strongest tier always?
[ad]would not require strongest tier always as would destroy portability, cleaner claim could be framework supports strong threat models when target exposes those surfaces while providing a portable baseline for opaque or minimally exposed systems.
[ae]I feel we always have proxied, so base may not be necessary?
Can make split simply between external and internal?
[af]Maybe we can make the external only using the 'target module'?
And also allow for internal when using the 'target runtime'?
[ag]would still probably keep base as minimal portability tier -> not every target will expose full proxy coverage, so base gives us a clean fallback while proxy and instrumented tiers capture richer visibility?


yes good simplification. target module can naturally provide external-facing observability and target runtime or instrumented adapter can provide internal observability when available.
[ah]from sure
[ai]What is the attack graph?