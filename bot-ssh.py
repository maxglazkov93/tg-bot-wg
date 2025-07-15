import logging
import tempfile
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ForceReply
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from wireguard_manager import WireGuardManager
from config import BOT_TOKEN, ACCESS_PIN

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Словарь для хранения состояний пользователей
user_states = {}

class WireGuardBot:
    def __init__(self):
        self.wg_manager = WireGuardManager()
        
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /start"""
        welcome_text = """
🔐 **WireGuard VPN Bot**

Этот бот создает конфигурации WireGuard для подключения к VPN серверу.

**Функции:**
• Создание нового клиентского конфига
• Автоматическое развертывание на сервере
• Защита PIN-кодом

Для создания конфигурации нажмите кнопку ниже и введите PIN-код.
        """
        
        keyboard = [
            [InlineKeyboardButton("🔑 Создать конфигурацию", callback_data="create_config")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            welcome_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /menu и кнопки Меню"""
        welcome_text = """
🔐 **WireGuard VPN Bot**

Этот бот создает конфигурации WireGuard для подключения к VPN серверу.

**Функции:**
• Создание нового клиентского конфига
• Автоматическое развертывание на сервере
• Защита PIN-кодом

Для создания конфигурации нажмите кнопку ниже и введите PIN-код.
        """
        keyboard = [
            [InlineKeyboardButton("🔑 Создать конфигурацию", callback_data="create_config")],
            [InlineKeyboardButton("📋 Меню", callback_data="menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        if update.message:
            await update.message.reply_text(
                welcome_text,
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
        elif update.callback_query:
            await update.callback_query.message.reply_text(
                welcome_text,
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
    
    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик нажатий на кнопки"""
        query = update.callback_query
        await query.answer()
        
        if query.data == "create_config":
            user_id = query.from_user.id
            user_states[user_id] = "waiting_pin"
            
            # Отправляем force_reply для PIN-кода
            sent = await query.message.reply_text(
                "🔐 **Введите PIN-код**\n\nДля создания конфигурации введите 6-значный PIN-код:",
                parse_mode='Markdown',
                reply_markup=ForceReply(selective=True)
            )
            # Сохраняем id сообщения для проверки reply
            context.user_data['pin_message_id'] = sent.message_id
            # Удаляем старое сообщение с кнопкой
            await query.delete_message()
        elif query.data == "menu":
            await self.menu(update, context)
            await query.delete_message()
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик текстовых сообщений"""
        user_id = update.message.from_user.id
        text = update.message.text
        logger.info(f"handle_message: user_id={user_id}, text={text}, state={user_states.get(user_id)}, reply_to={getattr(update.message.reply_to_message, 'message_id', None)}")
        
        # Проверяем, ожидается ли PIN и это reply на force_reply
        if user_states.get(user_id) == "waiting_pin":
            pin_message_id = context.user_data.get('pin_message_id')
            if update.message.reply_to_message and pin_message_id and \
               update.message.reply_to_message.message_id == pin_message_id:
                await self.handle_pin_input(update, context, text)
                return
            else:
                await update.message.reply_text("Пожалуйста, введите PIN-код, ответив на сообщение запроса PIN.")
                return
        elif user_states.get(user_id) == "waiting_name":
            name_message_id = context.user_data.get('name_message_id')
            if update.message.reply_to_message and name_message_id and \
               update.message.reply_to_message.message_id == name_message_id:
                await self.handle_name_input(update, context)
                return
            else:
                # Повторно отправляем force_reply для имени
                sent = await update.message.reply_text(
                    "Пожалуйста, введите имя для конфигурации (например: phone, laptop, tablet):",
                    parse_mode='Markdown',
                    reply_markup=ForceReply(selective=True)
                )
                context.user_data['name_message_id'] = sent.message_id
                return
        else:
            await update.message.reply_text(
                "Используйте /start для начала работы с ботом."
            )
            return
    
    async def handle_pin_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE, pin=None):
        """Обработчик ввода PIN-кода"""
        user_id = update.message.from_user.id
        if pin is None:
            pin = update.message.text.strip()
        else:
            pin = pin.strip()
        
        if pin == ACCESS_PIN:
            user_states[user_id] = "waiting_name"
            # Запрашиваем имя через force_reply
            sent = await update.message.reply_text(
                "✅ **PIN-код верный!**\n\nТеперь введите имя для конфигурации (например: phone, laptop, tablet):",
                parse_mode='Markdown',
                reply_markup=ForceReply(selective=True)
            )
            context.user_data['name_message_id'] = sent.message_id
        else:
            await update.message.reply_text(
                "❌ **Неверный PIN-код!**\n\n"
                "Попробуйте еще раз: ответьте на сообщение запроса PIN или нажмите /start."
            )
            del user_states[user_id]
            context.user_data.pop('pin_message_id', None)
    
    async def handle_name_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик ввода имени конфигурации"""
        user_id = update.message.from_user.id
        client_name = update.message.text.strip().lower()  # Приводим к нижнему регистру
        logger.info(f"handle_name_input: user_id={user_id}, client_name={client_name}")
        
        # Проверяем имя на допустимые символы (только латинские буквы в нижнем регистре, цифры, дефисы и подчеркивания)
        if not client_name.replace('_', '').replace('-', '').replace(' ', '').isalnum() or not client_name.isascii():
            sent = await update.message.reply_text(
                "❌ **Недопустимое имя!**\n\n"
                "Имя должно содержать только латинские буквы в нижнем регистре, цифры, дефисы и подчеркивания.",
                reply_markup=ForceReply(selective=True)
            )
            context.user_data['name_message_id'] = sent.message_id
            return
        
        # Проверяем, что имя содержит только латинские буквы в нижнем регистре
        if not all(c.islower() or c.isdigit() or c in '_-' for c in client_name):
            sent = await update.message.reply_text(
                "❌ **Недопустимое имя!**\n\n"
                "Используйте только латинские буквы в нижнем регистре, цифры, дефисы и подчеркивания.",
                reply_markup=ForceReply(selective=True)
            )
            context.user_data['name_message_id'] = sent.message_id
            return
        
        # Проверяем длину имени
        if len(client_name) < 2 or len(client_name) > 20:
            sent = await update.message.reply_text(
                "❌ **Недопустимая длина имени!**\n\n"
                "Имя должно содержать от 2 до 20 символов.",
                reply_markup=ForceReply(selective=True)
            )
            context.user_data['name_message_id'] = sent.message_id
            return
        
        # Проверяем, не существует ли уже конфигурация с таким именем
        if self.wg_manager.check_client_name_exists(client_name):
            sent = await update.message.reply_text(
                f"❌ **Конфигурация с именем '{client_name}' уже существует!**\n\n"
                "Пожалуйста, выберите другое имя.",
                reply_markup=ForceReply(selective=True)
            )
            context.user_data['name_message_id'] = sent.message_id
            return
        
        await update.message.reply_text(
            "⏳ **Создание конфигурации...**\n\n"
            "Пожалуйста, подождите. Это может занять несколько секунд.",
            parse_mode='Markdown'
        )
        
        try:
            # Создаем конфигурацию
            config, error = self.wg_manager.create_and_deploy_config(client_name)
            
            if error:
                await update.message.reply_text(
                    f"❌ **Ошибка создания конфигурации:**\n\n{error}"
                )
            else:
                # Создаем временный файл с конфигурацией
                with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
                    f.write(config)
                    temp_file_path = f.name
                
                # Отправляем файл конфигурации
                with open(temp_file_path, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"{client_name}.conf",
                        caption=f"✅ **Конфигурация создана!**\n\n"
                                f"📁 Файл: `{client_name}.conf`\n"
                                f"📱 Импортируйте этот файл в приложение WireGuard\n\n"
                                f"🔐 Конфигурация защищена и развернута на сервере.",
                        parse_mode='Markdown'
                    )
                
                # Удаляем временный файл
                os.unlink(temp_file_path)
                
                # Создаем кнопку для создания новой конфигурации
                keyboard = [
                    [InlineKeyboardButton("🔑 Создать еще одну", callback_data="create_config")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await update.message.reply_text(
                    "🎉 **Готово!**\n\n"
                    "Ваша конфигурация WireGuard создана и готова к использованию.",
                    reply_markup=reply_markup,
                    parse_mode='Markdown'
                )
        
        except Exception as e:
            await update.message.reply_text(
                f"❌ **Произошла ошибка:**\n\n{str(e)}"
            )
        
        finally:
            # Очищаем состояние пользователя
            if user_id in user_states:
                del user_states[user_id]
            context.user_data.pop('name_message_id', None)
            context.user_data.pop('pin_message_id', None)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /help"""
        help_text = """
🔧 **Справка по использованию бота**

**Команды:**
/start - Начать работу с ботом
/help - Показать эту справку

**Как использовать:**
1. Нажмите /start
2. Нажмите кнопку "Создать конфигурацию"
3. Введите PIN-код (6 цифр)
4. Введите имя для конфигурации
5. Получите файл .conf и импортируйте в WireGuard

**Требования:**
• PIN-код для доступа
• Приложение WireGuard на устройстве
• Стабильное интернет-соединение
        """
        
        await update.message.reply_text(help_text, parse_mode='Markdown')

def main():
    """Основная функция запуска бота"""
    bot = WireGuardBot()
    
    # Создаем приложение
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Добавляем обработчики
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("menu", bot.menu))
    application.add_handler(CallbackQueryHandler(bot.button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Запускаем бота
    print("🤖 WireGuard Bot запущен...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main() 