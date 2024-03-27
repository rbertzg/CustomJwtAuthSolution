namespace SharedClassLibrary.DTOs
{
    public class ServiceResponses
    {
        public record class GeneralResponse(bool Flag, string message);
        public record class LoginResponse(bool Flag, string Token, string message);
    }
}
