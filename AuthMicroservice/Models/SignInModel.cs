using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.Models;

public class SignInModel
{
    [EmailAddress]
    public string Email { get; set; } = null!;
    [MinLength(4)]
    public string Password { get; set; } = null!;
}
