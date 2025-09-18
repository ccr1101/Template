namespace Template.Options
{
    public class ClerkOptions
    {
        public string SecretKey { get; set; } = string.Empty;
        public string PublishableKey { get; set; } = string.Empty;
        public string[] AuthorizedParties { get; set; } = Array.Empty<string>();
        public string WebhookSecret { get; set; } = string.Empty;
    }
}
