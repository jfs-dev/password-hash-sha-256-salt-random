using password_hash_sha_256_salt_random.Models;
using password_hash_sha_256_salt_random.Services;

User peterPaker = new() { UserName = "Peter Parker", PasswordHash = PasswordService.CreatePasswordHash("Mary@Jane") };
User maryJane = new() { UserName = "Mary Jane", PasswordHash = PasswordService.CreatePasswordHash("Peter@Parker") };

Console.ForegroundColor = ConsoleColor.Magenta;
Console.WriteLine($"Usuário: { peterPaker.UserName } - Senha: { peterPaker.PasswordHash }");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine($"Senha válida? { PasswordService.VerifyPassword("Mary@Jane", peterPaker.PasswordHash) }");

Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Magenta;
Console.WriteLine($"Usuário: { maryJane.UserName } - Senha: { maryJane.PasswordHash }");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine($"Senha válida? { PasswordService.VerifyPassword("Peter@Parker", maryJane.PasswordHash) }");