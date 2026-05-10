package com.aluer.console;

import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.security.CommandExecutionGuardService;
import com.aluer.security.IntrusionDetectionService;
import com.aluer.service.RconClient;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class RemoteSshGatewayServiceTest {

    @Test
    void rejectsConnectionWithoutPasswordOrPrivateKey() {
        ServerGuardConfig config = new ServerGuardConfig();
        CommandExecutionGuardService commandGuard = new CommandExecutionGuardService(config, new IntrusionDetectionService());
        SecurityAuditService auditService = new SecurityAuditService(config, new RconClient(config));
        RemoteSshGatewayService service = new RemoteSshGatewayService(config, commandGuard, auditService);

        assertThrows(IllegalArgumentException.class, () -> service.connect(
            new RemoteSshGatewayService.ConnectRequest(
                "test-node",
                "127.0.0.1",
                22,
                "root",
                "",
                "",
                "",
                "",
                ""
            )
        ));
    }
}
