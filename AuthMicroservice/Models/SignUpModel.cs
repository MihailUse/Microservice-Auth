using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.Models;

public class SignUpModel
{
    [MinLength(4)]
    [MaxLength(255)]
    public string Login { get; set; } = null!;

    [EmailAddress]
    [MaxLength(255)]
    public string Email { get; set; } = null!;

    [MinLength(4)]
    [MaxLength(255)]
    public string Password { get; set; } = null!;
}
