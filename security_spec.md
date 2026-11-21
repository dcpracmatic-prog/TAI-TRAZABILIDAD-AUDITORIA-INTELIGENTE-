# Especificación de Seguridad — TAI (Trazabilidad y Auditoría Inteligente)

## 1. Invariantes de Datos
1. **Propiedad e Identidad Verificada**: Ningún operador puede crear un paquete, evento o registro de auditoría en nombre de otro `ownerId` ni sin correo verificado (`email_verified == true`).
2. **Integridad de Subcolección (Master Gate)**: Un `TraceEvent` en `/packages/{packageId}/events/{eventId}` solo puede crearse si el documento padre `/packages/{packageId}` existe y pertenece al usuario autenticado (o administrador).
3. **Inmutabilidad de Bitácora Maestra (`auditLogs`)**: Los registros en `auditLogs` son estrictamente de solo creación (`create`); ninguna actualización o eliminación es permitida por clientes, garantizando que la invalidación CSG de un CVV nunca destruya la evidencia maestra de auditoría.
4. **Bloqueo de Estados Terminales**: Un paquete en estado `audited` o un evento con `cvvState == 'invalidated_csg'` no puede revertirse por usuarios estándar.
5. **Aislamiento de Configuración Privada (`pilotConfigs`)**: Cada usuario solo lee y actualiza su propia configuración (`userId == request.auth.uid`).
6. **Integridad Temporal y Anti-Campos Fantasma**: Todos los timestamps `createdAt` y `updatedAt` se validan estrictamente contra `request.time`, y cada entidad aplica `keys().hasAll(...)` + `keys().hasOnly(...)` más límites de longitud `.size()`.

## 2. Payloads Adversarios ("Dirty Dozen")
1. **P01 — Spoofing de `ownerId` al crear paquete**: `ownerId: "otro_usuario"` distinto a `request.auth.uid` -> `PERMISSION_DENIED`.
2. **P02 — Correo no verificado**: `email_verified: false` con correo de administrador -> `PERMISSION_DENIED`.
3. **P03 — Campo fantasma en paquete ("Shadow Update")**: Incluir `isVerified: true` fuera del esquema permitido -> `PERMISSION_DENIED`.
4. **P04 — ID de paquete envenenado (>128 chars o caracteres inválidos)**: `packageId = "a".repeat(200)` o `"../admin"` -> `PERMISSION_DENIED`.
5. **P05 — Timestamp falsificado del cliente**: `createdAt` distinto de `request.time` -> `PERMISSION_DENIED`.
6. **P06 — Evento huérfano sin paquete padre**: Crear `/packages/NO_EXISTE/events/ev1` -> `PERMISSION_DENIED`.
7. **P07 — Eliminación de historial de auditoría**: `delete` sobre `/auditLogs/log1` -> `PERMISSION_DENIED`.
8. **P08 — Reversión de CVV invalidado por CSG**: `update` de `cvvState: "invalidated_csg"` a `"valid"` -> `PERMISSION_DENIED`.
9. **P09 — Lectura masiva sin filtro de propietario**: `list` en `/packages` de otro usuario -> `PERMISSION_DENIED`.
10. **P10 — Acceso cruzado a `pilotConfigs`**: Leer `/pilotConfigs/otro_uid` -> `PERMISSION_DENIED`.
11. **P11 — Desbordamiento de tamaño de texto ("Denial of Wallet")**: `observations` de 50,000 caracteres -> `PERMISSION_DENIED`.
12. **P12 — Mutación de campos inmutables en actualización**: Cambiar `ownerId` o `createdAt` al actualizar un paquete -> `PERMISSION_DENIED`.
