rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Helper function to check role in association
    function getRole(assoId) {
      return get(/databases/$(database)/documents/associations/$(assoId)/members/$(request.auth.uid)).data.role;
    }

    function isMember(assoId) {
      return exists(/databases/$(database)/documents/associations/$(assoId)/members/$(request.auth.uid));
    }

    match /associations/{assoId} {
      allow read: if isMember(assoId);
      allow create: if request.auth != null;
      allow update, delete: if getRole(assoId) == 'president';

      match /members/{memberId} {
        allow read: if isMember(assoId);
        allow write: if getRole(assoId) in ['president', 'secretaire'];
      }

      match /events/{eventId} {
        allow read: if isMember(assoId);
        allow create, update, delete: if getRole(assoId) in ['president', 'secretaire'];
      }
    }
  }
}