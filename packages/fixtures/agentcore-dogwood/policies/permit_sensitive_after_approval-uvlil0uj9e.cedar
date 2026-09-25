permit (
    principal == AgentCore::IamEntity::"arn:aws:iam::****:user/roe-operator",
    action == AgentCore::Action::"StatusTarget___do_sensitive",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:****:gateway/colophon-roe-gateway-dwg0z4emza"
)
when temporal {
    formerly within 1h AgentCore::Action::"StatusTarget___approve_action"::response{
        eventResource: resource,
        input.action:  context.input.action
    }
};
