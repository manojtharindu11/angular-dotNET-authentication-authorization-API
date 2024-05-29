namespace AngularAuthAPI.Models.DTO
{
    public class TokenApiDTO
    {
        public string AccessToken { get; set; } = string.Empty; 
        public string RefreshToken { get; set; } = string.Empty;
    }
}
