package dasniko.keycloak.resource;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
// import java.net.http.HttpRequest.BodyHandlers;
import java.util.Map;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@RequiredArgsConstructor
//@Path("/realms/{realm}/" + MyResourceProviderFactory.PROVIDER_ID)
public class MyResourceProvider implements RealmResourceProvider {

	private final KeycloakSession session;

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {
	}

	@GET
	@Path("hello")
	@Produces(MediaType.APPLICATION_JSON)
	@Operation(
		summary = "Public hello endpoint",
		description = "This endpoint returns hello and the name of the requested realm."
	)
	@APIResponse(
		responseCode = "200",
		description = "",
		content = {@Content(
			schema = @Schema(
				implementation = Response.class,
				type = SchemaType.OBJECT
			)
		)}
	)
	// public Response helloAnonymous() {
	// 	return Response.ok(Map.of("hello", session.getContext().getRealm().getName())).build();
	// }
    public Response helloAnonymous() {
        try {
            // 創建一個HttpClient實例
            HttpClient client = HttpClient.newHttpClient();
            // 創建請求體
            String requestBody = "{\n" +
                    "  \"service_account\": \"p_rbac_operator\",\n" +
                    "  \"token\": \"abc\"\n" +
                    "}";
            // 創建一個HttpRequest實例，設置請求URL、方法、頭和請求體
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://apiserver-admz.cloudcomputingmgmt-dev.dev.tsmc.com/rbac/get_all_role"))
                    .header("accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(requestBody))
                    .build();
            // 發送請求並接收響應
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            // 返回響應內容
            return Response.ok(Map.of("hello", response.body())).build();
        } catch (IOException | InterruptedException e) {
            // 處理異常情況
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }	
	}


	@GET
	@Path("hello1")
	@Produces(MediaType.APPLICATION_JSON)
	@Operation(
		summary = "Public hello endpoint",
		description = "This endpoint returns hello and the name of the requested realm."
	)
	@APIResponse(
		responseCode = "200",
		description = "",
		content = {@Content(
			schema = @Schema(
				implementation = Response.class,
				type = SchemaType.OBJECT
			)
		)}
	)
	public Response hello1Anonymous() {
		return Response.ok(Map.of("hello", session.getContext().getRealm().getName())).build();
	}


	@GET
	@Path("hello-auth")
	@Produces(MediaType.APPLICATION_JSON)
	public Response helloAuthenticated() {
		AuthResult auth = checkAuth();
		return Response.ok(Map.of("hello", auth.getUser().getUsername())).build();
	}

	private AuthResult checkAuth() {
		AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
		if (auth == null) {
			throw new NotAuthorizedException("Bearer");
		} else if (auth.getToken().getIssuedFor() == null || !auth.getToken().getIssuedFor().equals("admin-cli")) {
			throw new ForbiddenException("Token is not properly issued for admin-cli");
		}
		return auth;
	}
}
