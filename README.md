# password-hash-sha-256-salt-random
Usando o algoritmo de hash SHA-256 com SALT aleatório para armazenar e verificar senhas de forma segura em C#

![.Net](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white)
![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white)
![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-0078d7.svg?style=for-the-badge&logo=visual-studio-code&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)

## Sobre o projeto
Este projeto mostra como usar o algoritmo de hash SHA-256 com SALT aleatório para armazenar e verificar senhas de forma segura em C#.

A escolha da melhor opção para criptografar uma senha depende de vários fatores, incluindo segurança, desempenho e facilidade de implementação.
Esta é uma abordagem comum onde você aplica um algoritmo de hash como SHA-256 ou SHA-512 para a senha, juntamente com um valor aleatório chamado "salt".

**SHA-256:** Usa um tamanho de bloco de 512 bits e produz hashes de 256 bits. É amplamente utilizado e é uma boa escolha para muitos cenários de segurança.

**SHA-384:** Usa um tamanho de bloco de 1024 bits e produz hashes de 384 bits.

**SHA-512:** Usa um tamanho de bloco de 1024 bits e produz hashes de 512 bits. É uma variante mais segura, porém mais lenta, do que o SHA-256.

<div align="center">
    <img src="https://github.com/jfs-dev/password-hash-sha-256-salt-random/assets/54154628/5fba8721-bdec-40fd-822f-627c9c1070db"</img>
</div>

## Referências
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256?view=net-8.0

## Licença
GPL-3.0 license
