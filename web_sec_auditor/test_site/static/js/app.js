// Archivo JS del frontend
const STRIPE_PUBLIC = "pk_test_51Mz0FakeStripeKeyForTesting123";
const FIREBASE_DB = "https://test-project-demo.firebaseio.com";

// Endpoints internos
async function loadUserData() {
    const res = await fetch("/api/v1/profile");
    return res.json();
}

function checkAdmin() {
    axios.get("/admin/dashboard/stats");
}
