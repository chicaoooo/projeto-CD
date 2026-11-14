package pt.upt.cd.BlocoAutorizacao;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;

public class BlocoAutorizacao {
    private String hashAnterior;
    private String hashAtual;
    private String aluno;
    private String encarregadoEducacao;
    private String detalhesSaida;
    private long timestamp;
    private String assinaturaDigital;

    public BlocoAutorizacao(String aluno, String encarregadoEducacao, String detalhesSaida, String hashAnterior, String assinaturaDigital) {
        this.aluno = aluno;
        this.encarregadoEducacao = encarregadoEducacao;
        this.detalhesSaida = detalhesSaida;
        this.hashAnterior = hashAnterior;
        this.assinaturaDigital = assinaturaDigital;
        this.timestamp = new Date().getTime();
        this.hashAtual = calcularHash();
    }

    public String calcularHash() {
        String dadosParaHasear = hashAnterior + longToString(timestamp) + aluno + encarregadoEducacao + detalhesSaida + assinaturaDigital;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(dadosParaHasear.getBytes(StandardCharsets.UTF_8));
            StringBuilder buffer = new StringBuilder();
            for (byte b : hashBytes) {
                buffer.append(String.format("%02x", b));
            }
            return buffer.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String longToString(long l) {
        return Long.toString(l);
    }

    public String getHashAtual() { return hashAtual; }
    public String getHashAnterior() { return hashAnterior; }
    public String getAluno() { return aluno; }
    public String getAssinaturaDigital() { return assinaturaDigital; }
}