import { handler } from './index'; 

async function test() {
  const event = {
    body: JSON.stringify({
      cpf: '44884763840',
      password: '@Aprendiz17',
    }),
  };

  const result = await handler(event);
  console.log(result);
}

test();
