package pt.upt.cd.verificacao_de_assinatura_digital_escolar;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
// Nota: Ajusta o import abaixo se a classe BlocoAutorizacao estiver no mesmo pacote
import pt.upt.cd.BlocoAutorizacao.BlocoAutorizacao; 

public class Verificacao_de_assinatura_digital_escolar {

    private static List<BlocoAutorizacao> blockchain = new ArrayList<>();

    // Método auxiliar para assinar digitalmente a autorização (feito pelo Encarregado de Educação)
    public static String assinarAutorizacao(PrivateKey chavePrivada, String dados) throws Exception {
        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initSign(chavePrivada);
        assinatura.update(dados.getBytes());
        byte[] assinaturaBytes = assinatura.sign();
        return Base64.getEncoder().encodeToString(assinaturaBytes);
    }

    // Método auxiliar para verificar a assinatura (feito pela Portaria / Escola)
    public static boolean verificarAssinatura(PublicKey chavePublica, String dados, String assinaturaStr) throws Exception {
        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initVerify(chavePublica);
        assinatura.update(dados.getBytes());
        byte[] assinaturaBytes = Base64.getDecoder().decode(assinaturaStr);
        return assinatura.verify(assinaturaBytes);
    }

    public static void main(String[] args) {
        try {
            System.out.println("=== SISTEMA DE CADERNETA ESCOLAR DIGITAL & BLOCKCHAIN ===");
            System.out.println("Alunos: 26407 Francisco Margarido | 27230 Kanstantsin Khomchanka\n");

            // 1. Simular a geração de chaves criptográficas para o Encarregado de Educação
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair parChavesEE = keyGen.generateKeyPair();
            PrivateKey chavePrivadaEE = parChavesEE.getPrivate();
            PublicKey chavePublicaEE = parChavesEE.getPublic();

            // --- BLOCO 1: Primeira Autorização de Saída ---
            String dadosSaida1 = "Aluno: Francisco Margarido | Saída autorizada às 16:30 para consulta médica.";
            System.out.println("-> Encarregado a assinar a autorização 1...");
            String assinatura1 = assinarAutorizacao(chavePrivadaEE, dadosSaida1);

            String hashGenesis = "0";
            BlocoAutorizacao bloco1 = new BlocoAutorizacao(
                "Francisco Margarido", 
                "Pai / Encarregado de Educação", 
                dadosSaida1, 
                hashGenesis, 
                assinatura1
            );
            blockchain.add(bloco1);
            System.out.println("-> Bloco 1 adicionado. Hash Atual: " + bloco1.getHashAtual() + "\n");

            // --- BLOCO 2: Segunda Autorização de Saída (Encadeado ao Bloco 1) ---
            String dadosSaida2 = "Aluno: Kanstantsin Khomchanka | Saída autorizada às 17:00 para atividade escolar.";
            System.out.println("-> Encarregado a assinar a autorização 2...");
            String assinatura2 = assinarAutorizacao(chavePrivadaEE, dadosSaida2);

            // O Bloco 2 guarda o hash do Bloco 1 como hashAnterior
            BlocoAutorizacao bloco2 = new BlocoAutorizacao(
                "Kanstantsin Khomchanka", 
                "Mãe / Encarregado de Educação", 
                dadosSaida2, 
                bloco1.getHashAtual(), 
                assinatura2
            );
            blockchain.add(bloco2);
            System.out.println("-> Bloco 2 adicionado (ligado ao Bloco 1). Hash Atual: " + bloco2.getHashAtual() + "\n");

            // 5. Portaria valida a autorização e a assinatura do Bloco 1
            System.out.println("[PORTARIA] A verificar autenticidade da saída do Bloco 1...");
            boolean assinaturaValida1 = verificarAssinatura(chavePublicaEE, dadosSaida1, bloco1.getAssinaturaDigital());
            
            if (assinaturaValida1) {
                System.out.println("[SUCESSO] A assinatura digital do Bloco 1 é válida! Saída autorizada.");
            } else {
                System.out.println("[ALERTA] Assinatura inválida no Bloco 1!");
            }

            // Validação da cadeia completa (Demonstração da Imutabilidade)
            System.out.println("\n[SISTEMA] A verificar integridade da cadeia de blocos...");
            boolean cadeiaIntegra = true;
            for (int i = 1; i < blockchain.size(); i++) {
                BlocoAutorizacao atual = blockchain.get(i);
                BlocoAutorizacao anterior = blockchain.get(i - 1);
                
                // Verifica se o hash anterior bate certo e se o hash atual foi recalculado corretamente
                if (!atual.getHashAnterior().equals(anterior.getHashAtual()) || !atual.getHashAtual().equals(atual.calcularHash())) {
                    cadeiaIntegra = false;
                    break;
                }
            }

            if (cadeiaIntegra) {
                System.out.println("[SUCESSO] A Blockchain está íntegra e segura! Total de blocos: " + blockchain.size());
            } else {
                System.out.println("[ERRO] A Blockchain foi adulterada!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}