import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;


public class GPTRequest {
    public static void main(String[] args) throws URISyntaxException, IOException, InterruptedException {
//        String apiKey = "[insert your own API key here]";
//        String prompt = "The quick brown fox";
//        int length = 10;
//        String url = "https://api.openai.com/v1/chat/completions";
//
//        String json = "{"
//                + "\"model\":\"gpt-3.5-turbo\","
//                + "\"messages\":[{\"role\":\"user\",\"content\":\"" + prompt + "\"}],"
//                + "\"max_tokens\":" + 3500
//                + "}";
//
//        HttpClient client = HttpClient.newHttpClient();
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(new URI(url))
//                .header("Content-Type", "application/json")
//                .header("Authorization", "Bearer " + apiKey)
//                .POST(HttpRequest.BodyPublishers.ofString(json))
//                .build();
//
//        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String apiKey = "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";
        String prompt = "The following code is output from ghidra decompilation, summarize what the function does:";// + decompilationResults.getDecompiledFunction().getC();
//                String model = "gpt-3.5-turbo";
        String url = "https://api.openai.com/v1/chat/completions";
        int maxTokens = 3500;

        System.out.println(prompt);
        prompt = StringEscapeUtils.escapeJava(prompt);

        // Set up the API request
        String json = "{"
                + "\"model\":\"gpt-3.5-turbo\","
                + "\"messages\":[{\"role\":\"user\",\"content\":\"" + prompt + "\"}],"
                + "\"max_tokens\":" + maxTokens
                + "}";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());



        // Print the response
//                System.out.println(response.toString());
//        println(function.getName() + "\n\n");
//        println(response + "\n\n\n");
        System.out.println(response.body());
    }
}

